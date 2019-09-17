/*
 	Remote Connection Manager - is a research prototype of the
 	"Application-agnostic remote access for Bluetooth Low Energy"
 	first introduced in https://ieeexplore.ieee.org/document/8406942/

    Copyright (C) <2018>  <Nokia Bell Labs France>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

	Natalya Rozhnova <natalya.rozhnova@nokia-bell-labs.com>
	Marc-Olivier Buob <marc-olivier.buob@nokia-bell-labs.com>
	Hui YIN <phoebe_yin@msn.com>
*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "src/plugin.h"
#include "config.h" // for STORAGEDIR
#include "limits.h" // for PATH_MAX

#include "src/gatt-client.h"

/////////////////////
#include <stdint.h>
#include <string.h>
#include <glib.h>
#include <stdlib.h>     // strtol
#include <string.h>     // memset
#include <ctype.h>      // isxdigit
#include <stdbool.h>    // bool
#include <sys/socket.h>

#include "bluetooth/bluetooth.h"    // needed by adapter.h
#include "bluetooth/sdp.h"          // needed by adapter.h

#include "lib/hci.h"
#include "lib/bluetooth.h"
#include "monitor/bt.h"
/////////////////////

// For socket management
#include <stdio.h>
#include <unistd.h>    //write
#include <arpa/inet.h> //inet_addr

// Custom for RCM
//#include "rcm_structures.h"
#include "complete_structures.h"
#include "common.h"
//#include "rcm_help_func.h"


#include <sys/sendfile.h>
#include <fcntl.h>

#include <sys/time.h>
#include <sys/stat.h>

#include <gio/gnetworking.h>

//#include <dbus/dbus.h>
//#include <dbus/dbus-glib.h>
//#include <gio/gio.h>
//#include <netinet/in.h>

// Yes, that's dirty, I know, it's a temporary solution
#include "dbus-server.c"

//For dbus
//#include "gdbus/gdbus.h"

// --------------------------------------------------------------------------------------------------
#define BLUEZ_BUS_NAME "org.bluez"
#define BLUEZ_INTF_ADAPTER "org.bluez.Adapter1"
#define BLUEZ_INTF_DEVICE "org.bluez.Device1"
#define BLUEZ_INTF_CHAR "org.bluez.GattCharacteristic1"
#define BLUEZ_INTF_DESC "org.bluez.GattDescriptor1"

//HUI
#define NB_ADV_MAX_FILTER_SET 3
#define NB_ADV_MAX_NO_FILTER 100

///////////////////////////
#define BUFFER_QUERY_SIZE 3000
#define BUFFER_REPLY_SIZE 3000
#define NB_RTX	3

// --------------------------------------------------------------------------------------------------

static DBusConnection *dbus_connection = NULL;

//static bool send_scan_results = true; // XXX Temporary for debugging !!! Should be removed
static gboolean can_send = TRUE;
static bool sending_cache_info = false;

// How many advertisements will be sent to the remote client
// there is no need to send all of them, the limited amount (even 1) is sufficient.
// We use 3 (cf. NB_ADV_MAX) by default to protect against the packet loss
//static int nb_advertisements = 0;

struct btd_adapter * default_adapter;
GThreadedSocketService * service = NULL;
static bool discovery_is_running = false;

// Remote clients ---------------------------------------------------------------------
// Exists as a separate structure because of app_id only.
// app_id is a field in the packet so it wouldn't be so easy to remove this from proxy
// the client should also be modified...
typedef struct remote_client_application {
	char *app_id;
//	uint8_t wait_for_reply; // the code of the message the client is waiting for reply to
	uint16_t pending_reply_codes;	// each of these cells(from 1 to 11) corresponds to a command
										// If a command number presents in a corresponding cell (not 0x00)
										// It means that the command is pending and we are waiting for a reply
										// For example, pending_reply_codes[1] == 0x01 => we are waiting for START_DISCOVERY reply
										// If we are not waiting for that, pending_reply_codes[1] should be = 0x00 (default)
	int nb_advertisements;
	GSList *uuids;
} RemoteClientApplication;

// Created once a remote client connects to our proxy
typedef struct active_client {
	char * mac_address;
	GSocketConnection * connection; // socket connection corresponding to a given client
	GSList *remote_client_apps;		// List of RemoteClientApplication to support multi-apps activity
	GSList *authorized_devices;		// devices allowed to be detected by this given client

	// For device connection
	bool has_cache_info;

} ActiveClient;

GSList *active_clients = NULL;		// List of ActiveClient
// ------------------------------------------------------------------------------------

// Proxy devices ----------------------------------------------------------------------
typedef struct known_device {
	struct btd_device *device;
	uint8_t *adv_reply;
	size_t adv_size;
	bool device_connected;
} KnownDevice;

GSList *known_devices_list = NULL;	// Devices known by this proxy
// ------------------------------------------------------------------------------------

// Response management ----------------------------------------------------------------
// If a response packet can't be send immediately (socket busy etc.) it will be put in a queue
typedef struct data_payload {
	uint8_t reply_code;
	gpointer data;
	gsize data_len;
} DataPayload;

typedef struct response_pkt {
	uint8_t *data_to_send;
	size_t data_len;
	guint16 port;
	GSocketConnection * connection;
	uint8_t reply_code;
	uint8_t nb_rtx;
} ResponsePkt;

GAsyncQueue * output_queue;

// Used to pass a user_data to glib functions
typedef struct userdata{
	GSocketConnection *connection;
	DataPayload *payload;
	// May be needed in some specific cases:
	gboolean dev_authorized;
	gboolean stop_flag; //For example, in case of start discovery data, this flag will serve to check whether at least one client
				   // is still waiting for a start discovery result. If no client is interested in this data, we will stop discovery.
	char *addr;	   // May be needed to check whether a client is authorized to detect the found device
	GSList *filters;
	char *appid;
}UserData;

// Parse received packed's header
typedef struct{
	ssize_t pkt_len;
	char mac_addr[18]; // Do we really need it as string?
	uint8_t appid_len;
	char *appid;
	uint8_t opcode;
}RCMHeader;

typedef struct{
	size_t eir_len;
	uint8_t addr_type;
	const bdaddr_t *bdaddr;
	const uint8_t *eir;
	char *addr;
	GSList *services;
}RCMStartDiscovery;

typedef struct{
	// some common info
	uint8_t reply_code;
	size_t reply_size;
	union{
		RCMStartDiscovery dev_detected;
		// TODO: other ones
	}reply_type;
}ProxyReply;
// ------------------------------------------------------------------------------------

// Device connection management -------------------------------------------------------

typedef struct connected_device_data {
	struct btd_device *device;
	struct btd_adapter * adapter;
	GSList *client_list;					// contains *ActiveClient
	uint8_t *connection_reply;//[BUFFER_REPLY_SIZE];//new
	size_t connection_reply_len;//new
	bool remote_connected;//new
} ConnectedDeviceData;

GSList *connected_device_list = NULL;//HUI
// ------------------------------------------------------------------------------------

static bool discovery_started_remotely = false;

// TODO: this is a temporary version
// TODO: The whole code should be redesigned in future
typedef struct {
	uint16_t handle[20];
	size_t n_handles;
	bdaddr_t bdaddr;
}DeviceSubscription;

typedef struct {
	DeviceSubscription *subscr;
//	size_t num_dev; // for future use, to authorize more than 1 device
	GSocketConnection * connection;
}NotificationSubscribers;

GSList *notification_subscribers = NULL; // stores NotificationSubscribers elements

typedef struct {
	unsigned int id;
	uint16_t handle;
	GSocketConnection * connection;
	uint8_t bdaddr[6];
}WriteId;

GSList *write_ids = NULL;
// End of multiclient
/*
 * TODO: to detect the same device twice: locally and remotely
 * For remote detection we also need to modify the device name in eir to add "(Remote)" info
 */

typedef struct {
	bdaddr_t real_bdaddr;
	uint8_t virt_bdaddr[6];
	GSocketConnection * connection;
}BTAddrMapping;

uint8_t free_device_id = 0x00; // 254 devices should be sufficient. If not, just change the type of this value to use more bytes.
uint8_t dev_id_base[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
GSList *addr_mapping_list = NULL;

// --------------------------------------------------------------------------------------------------
static void rcm_send_packet( GSocketConnection	*connection,
						 DataPayload *payload);

static void rcm_process_cmd_stop_discovery( struct btd_adapter	*adapter);

static void rcm_send_bytes_async( GSocketConnection		*connection,
							  gpointer			 	 data,
							  GAsyncReadyCallback	 callback // Pass NULL to use the default callback 'rcm_callback_send_bytes_async' (see common.c)
							 );

static void rcm_init_pending_response(ResponsePkt *response);

static void rcm_free_allocated_memory(void);

static void rcm_cb_connection_result( uint16_t		 index,
									  uint16_t		 length,
									  const void	*param,
									  void			*user_data);

guint16 rcm_get_connection_port( GSocketConnection	*connection);

static void rcm_trigger_new_discovery( struct btd_adapter	*adapter);

static void rcm_disconnect_device( struct btd_device	*device);

void rcm_make_active_clients_gvariant( ActiveClient		*connection,
									   gpointer			 user_data);

ActiveClient *rcm_get_client_by_mac_addr( char	*mac_addr);

// ============================================================================
// Printing
// ============================================================================

static void rcm_print_appid( RemoteClientApplication	*remote_client_application,
						 gpointer		 user_data)
{
    TRACE_FUNCTION;
	DBG("remote_client_application->app_id = %s\n",
			remote_client_application->app_id);
}

static void rcm_print_active_client( ActiveClient	*connection,
						   gpointer user_data)
{
    TRACE_FUNCTION;
	g_printf("List elements: port = %d, connection = %p\n",
			rcm_get_connection_port(connection->connection), connection->connection);
}

static void rcm_print_connection( GSocketConnection	*connection)
{
    TRACE_FUNCTION;
	GSocketAddress *sockaddr = g_socket_connection_get_remote_address(connection, NULL);
	GInetAddress *addr = g_inet_socket_address_get_address(G_INET_SOCKET_ADDRESS(sockaddr));
	guint16 port = g_inet_socket_address_get_port(G_INET_SOCKET_ADDRESS(sockaddr));
	DBG("New Connection from %s:%d\n", g_inet_address_to_string(addr), port);
}

void rcm_print_fd(GSocketConnection *conn, const char *func){
	GSocket *socket = g_socket_connection_get_socket(conn);
	int fd = g_socket_get_fd(socket);
	printf("SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS\n");
	printf("%s connection = %p socket fd = %d\n",func, conn, fd);
	printf("SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS\n");
}

void rcm_print_mapping_element(BTAddrMapping *element)
{
        printf("Real: ");
        for(int i=0; i<6; i++)
                printf("%02x ", element->real_bdaddr.b[i]);

        printf("Virt: ");
        for(int i=0; i<6; i++)
                printf("%02x ", element->virt_bdaddr[i]);

        printf("Connection %p\n", element->connection);

        printf("\n");
}

//==========================================================================
// BT address mapping
//==========================================================================

int find_mapping_real(gconstpointer a, gconstpointer b){
        const BTAddrMapping *el = (BTAddrMapping *)a;
        const bdaddr_t *addr = (bdaddr_t *)b;
        for(int i=0; i<6; i++){
                if(el->real_bdaddr.b[i] != addr->b[i])
                        return -1;
        }
return 0;
}

int find_mapping_virt(gconstpointer a, gconstpointer b){
        const BTAddrMapping *el = (BTAddrMapping *)a;
        const uint8_t *addr = (uint8_t *)b;
        for(int i=0; i<6; i++){
                if(el->virt_bdaddr[i] != addr[i])
                        return -1;
        }
return 0;
}

BTAddrMapping * map_address(const bdaddr_t *addr)
{
        GSList *l = g_slist_find_custom(addr_mapping_list, addr, find_mapping_real);
        if(l) return (BTAddrMapping *)l->data;

        BTAddrMapping *new_item = (BTAddrMapping *) malloc(sizeof(BTAddrMapping));
        if(!new_item) return NULL;

        memcpy(&(new_item->real_bdaddr), addr, 6);
        free_device_id++;
        dev_id_base[5] = free_device_id;
        memcpy(&(new_item->virt_bdaddr), &dev_id_base, 6);

        new_item->connection = NULL;
        addr_mapping_list = g_slist_append(addr_mapping_list, new_item);
        return new_item;
}

int connection_mapped(gconstpointer a, gconstpointer b){
	const BTAddrMapping *el = (BTAddrMapping *)a;
	const GSocketConnection *conn = (GSocketConnection *)b;

	if(el->connection == conn)
		return 0;
	return -1;
}

//==========================================================================
// Checking
//==========================================================================

gboolean rcm_connection_exists(gchar *mac)
{
	ActiveClient *connection = rcm_get_client_by_mac_addr(mac);
	if(!connection) return FALSE;
	return TRUE;
}

GSList * rcm_check_autorized(gchar *mac, gchar *address)
{
	ActiveClient *connection = rcm_get_client_by_mac_addr(mac);
	if(!connection) return NULL;

	return g_slist_find_custom(connection->authorized_devices, address,	rcm_gdbus_find_filter_element);
}
// Not used
gboolean rcm_ignore_discovery(GSocketConnection *connection)
{
	GSList *l = g_slist_find_custom(addr_mapping_list, connection, connection_mapped);
	if(!l) return FALSE;
	return TRUE;
}
// ============================================================================
// Configuration
// ============================================================================

static void rcm_gdbus_config(){
    TRACE_FUNCTION;
	DBusError* error = NULL;

	dbus_connection = dbus_bus_get(DBUS_BUS_SYSTEM, error);

	if(error)
	{
		DBG("Unable to get dbus connection %s\n", error->message);
	}
	DBG("Got DBus connection %p\n", dbus_connection);

}

// ============================================================================
// Comparison
// ============================================================================

gint g_strcmp( gconstpointer a,
					  gconstpointer b){
	TRACE_FUNCTION;
	return strcmp(a, b);
}

static int rcm_cmp_connection_id( gconstpointer a,
							  gconstpointer b){
	TRACE_FUNCTION;
	const ActiveClient *conn = a;
	const GSocketConnection *connection = b;

	return conn->connection == connection ? 0 : -1;
}

static int rcm_cmp_mac_address( gconstpointer a,
							gconstpointer b){
	TRACE_FUNCTION;
	const ActiveClient *conn = a;
	const char *mac_addr = b;

	if(conn->mac_address == NULL)
		return -1;
	else
		return g_strcmp(conn->mac_address, mac_addr);
}

static int rcm_cmp_known_device( gconstpointer a,
							 gconstpointer b){
	TRACE_FUNCTION;
	const KnownDevice *known_dev = a;
	const struct btd_device *device = b;
	return known_dev->device == device ? 0 : -1;
}

static int rcm_cmp_connected_device( gconstpointer a,
								 gconstpointer b){
    TRACE_FUNCTION;
	const ConnectedDeviceData *connected_dev_data = a;
	const struct btd_device *device = b;
	return connected_dev_data->device == device ? 0 : -1;
}

static int rcm_cmp_app_id( gconstpointer a,
					   gconstpointer b){
	TRACE_FUNCTION;
	const RemoteClientApplication *remote_client_application = a;
	const char *app_id = b;

	DBG("RCM: remote_client_application->app_id = %s, new appid = %s\n", remote_client_application->app_id, app_id);

	if(!strcmp(remote_client_application->app_id, app_id))
		return 0;

	return -1;
//	return g_strcmp(remote_client_application->app_id, app_id);
}

static bool rcm_is_discovery_filter_match( GSList	*discovery_filter,
									GSList	*dev_uuids){
	TRACE_FUNCTION;
	GSList *m;
	bool got_match = false;

	if (!discovery_filter)
		got_match = true;
	else {
		for (m = discovery_filter; m != NULL && got_match == false; m = m->next) {
			if (g_slist_find_custom(dev_uuids, m->data, g_strcmp) != NULL){
				got_match = true;
			}
		}
	}
	return got_match;
}

static int rcm_cmp_notification_subscriber( gconstpointer a,
					   	    gconstpointer b){
	const NotificationSubscribers *subscr = a;
	const GSocketConnection		*connection = b;

	if(subscr->connection == b)
		return 0;

	return -1;
}

gboolean rcm_compare_bdaddr(bdaddr_t addr1, bdaddr_t addr2)
{
	for(int i=0; i<6; i++)
	{
		if(addr1.b[i] != addr2.b[i])
			return FALSE;
	}
	return TRUE;
}

// ============================================================================
// Getters
// ============================================================================

guint16 rcm_get_connection_port( GSocketConnection *connection){
	TRACE_FUNCTION;
	DBG("connection = %p\n", connection);
	GSocketAddress *sockaddr = g_socket_connection_get_remote_address(connection, NULL);
	guint16 port = g_inet_socket_address_get_port(G_INET_SOCKET_ADDRESS(sockaddr));

	return port;
}

char * rcm_get_connection_addr( GSocketConnection *connection){
	TRACE_FUNCTION;
	DBG("connection = %p\n", connection);
	GSocketAddress *sockaddr = g_socket_connection_get_remote_address(connection, NULL);
	GInetAddress *addr = g_inet_socket_address_get_address(G_INET_SOCKET_ADDRESS(sockaddr));
	char* conn_addr = g_inet_address_to_string(addr);
	return conn_addr;
}

ActiveClient *rcm_get_client_by_connection_id( GSocketConnection *connection){
	TRACE_FUNCTION;
	GSList *list;
	ActiveClient *c_connection;

	DBG("Looking for connection = %p\n", connection);
	list = g_slist_find_custom(active_clients, connection, rcm_cmp_connection_id);
	if (!list)
	{
		DBG("Corresponding connection wasn't found!\n");
		return NULL;
	}

	c_connection = list->data;

	return c_connection;
}


ActiveClient *rcm_get_client_by_mac_addr( char	*mac_addr){
	TRACE_FUNCTION;
	GSList *list;
	ActiveClient *c_connection;

	DBG("Looking for mac address in active connection = %s\n", mac_addr);
	list = g_slist_find_custom(active_clients, mac_addr, rcm_cmp_mac_address);
	if (!list)
	{
		DBG("Corresponding mac address wasn't found!\n");
		return NULL;
	}

	c_connection = list->data;

	return c_connection;
}

KnownDevice *rcm_get_device_in_known_device_list( struct btd_device *device){
	TRACE_FUNCTION;
	GSList *list;
	KnownDevice *known_dev;
	list = g_slist_find_custom(known_devices_list, device, rcm_cmp_known_device);
	if (!list)
	{
		DBG("RCM: Corresponding device wasn't found!\n");
		return NULL;
	}
	known_dev = list->data;
	return known_dev;
}

ConnectedDeviceData *rcm_get_connected_dev_by_filter( GSList *uuids){
	TRACE_FUNCTION;
	GSList *l;
	for(l = connected_device_list; l != NULL; l = l->next)
	{
		ConnectedDeviceData *connected_dev_data = l->data;

		if(rcm_is_discovery_filter_match(uuids, connected_dev_data->device->uuids))
		{
			return connected_dev_data;
		}
	}
	DBG("RCM: no matching device!!\n");
	return NULL;
}

ConnectedDeviceData *rcm_get_device_in_connected_device_list( struct btd_device	*device){
    TRACE_FUNCTION;
	GSList *list;
	ConnectedDeviceData *connected_dev_data;
	list = g_slist_find_custom(connected_device_list, device, rcm_cmp_connected_device);
	if (!list)
	{
		DBG("RCM: Corresponding device wasn't found!\n");
		return NULL;
	}
	connected_dev_data = list->data;
	return connected_dev_data;
}

static int rcm_get_active_client( gconstpointer a,
							 gconstpointer b)
{
    TRACE_FUNCTION;
	const ActiveClient *active_client = a;
	const GSocketConnection * connection = b;

	return active_client->connection == connection ? 0 : -1;
}

static int rcm_get_subscriber_by_handle( gconstpointer a,
									   gconstpointer b)
{
	const NotificationSubscribers *subscr = a;
	const uint16_t handle = GPOINTER_TO_UINT(b);

	if(!subscr) return -1;

	DBG("rcm_get_subscriber_by_handle %02x n_handles = %d\n", handle, subscr->subscr->n_handles);

	for(int i=0; i<subscr->subscr->n_handles; i++){
		DBG("rcm_get_subscriber_by_handle subscr->handle = %02x\n", subscr->subscr->handle[i]);
		if(subscr->subscr->handle[i] == (handle+1))
			return 0;
	}
	return -1;

}

static int rcm_get_write_id(gconstpointer a, gconstpointer b)
{
	const WriteId *element = a;
	const uint16_t handle = GPOINTER_TO_UINT(b);

	if(element->handle == handle)
		return 0;
	return -1;
}

static int rcm_get_write_handle(gconstpointer a, gconstpointer b)
{
	const WriteId *element = a;
	const unsigned int id = GPOINTER_TO_UINT(b);

	if(element->id == id)
		return 0;
	return -1;
}

RemoteClientApplication *rcm_get_remote_app_by_app_id( GSocketConnection	*connection,
										   char					*app_id)
{
	TRACE_FUNCTION;
	GSList *list;
	ActiveClient *active_client;
	RemoteClientApplication *remote_client_application;

	active_client = rcm_get_client_by_connection_id(connection);
	DBG("active_client %p\n", active_client);
	g_slist_foreach(active_client->remote_client_apps, (GFunc)rcm_print_appid, NULL);

	list = g_slist_find_custom(active_client->remote_client_apps, app_id, rcm_cmp_app_id);
	if (!list)
	{
		DBG("RCM: Corresponding client wasn't found!\n");
		return NULL;
	}
	remote_client_application = list->data;
	return remote_client_application;
}

static void rcm_cb_get_active_clients(void *g_v_builder)
{
    TRACE_FUNCTION;

	g_slist_foreach(active_clients, (GFunc)rcm_make_active_clients_gvariant, g_v_builder);

}

static int rcm_get_ip( ActiveClient *active_conn,
					GInetAddress *ip_addr)
{
	GSocketAddress *socket_addr = g_socket_connection_get_remote_address(active_conn->connection, NULL);
	GInetAddress *active_ip_addr = g_inet_socket_address_get_address(G_INET_SOCKET_ADDRESS(socket_addr));
	return g_inet_address_equal(active_ip_addr, ip_addr) ? 0 : 1;
}

GSList * rcm_get_active_client_ip(GSList *connections, GSocketConnection *connection)
{
	GSocketAddress *socket_addr = g_socket_connection_get_remote_address(connection, NULL);
	GInetAddress *client_addr = g_inet_socket_address_get_address(G_INET_SOCKET_ADDRESS(socket_addr));

	return g_slist_find_custom(connections, client_addr, (int (*)(gconstpointer, gconstpointer)) rcm_get_ip);
}

void rcm_get_client_filter(gchar *mac, void *g_v_builder)
{
    TRACE_FUNCTION;

    ActiveClient *connection = rcm_get_client_by_mac_addr(mac);

    if(!connection || connection->authorized_devices == NULL)
    {
    	g_variant_builder_add ((GVariantBuilder *)g_v_builder, "s", "empty");
    	return;
    }

    g_slist_foreach(connection->authorized_devices, (GFunc)make_filter_gvariant, g_v_builder);
}

// ============================================================================
// Setters
// ============================================================================

static void rcm_set_new_wait_code( GSocketConnection	*connection,
							   char					*app_id,
							   uint8_t				 new_code)
{
    TRACE_FUNCTION;
	RemoteClientApplication *remote_client_application;

	DBG("for connection = %p, app_id = %s\n", connection, app_id);
	remote_client_application = rcm_get_remote_app_by_app_id(connection, app_id);

	// Only one copy of each code should be there
	// START and STOP can't exist at the same time and should replace each other
	switch(new_code){
	case REMOTE_CMD_START_DISCOVERY:{
		// Clear for STOP_DISCOVERY
		uint8_t shift = REMOTE_CMD_STOP_DISCOVERY - 1;
		remote_client_application->pending_reply_codes &= ~(1 << shift);
		break;
	};
	case REMOTE_CMD_STOP_DISCOVERY:{
		// Clear START_DISCOVERY
		uint8_t shift = REMOTE_CMD_START_DISCOVERY - 1;
		remote_client_application->pending_reply_codes &= ~(1 << shift);
		break;
	}
	case REMOTE_CMD_CONNECT_DEVICE:{
		// Should be removed when CONNECT response is sent
		break;
	}
	}
//	DBG("old code = %s\n", code_to_str(remote_client_application->wait_for_reply));
	uint8_t shift = new_code - 1;
	remote_client_application->pending_reply_codes |= (1<<shift);
//	DBG("new code = %s\n", code_to_str(remote_client_application->wait_for_reply));
}


// ============================================================================
// Init/Create
// ============================================================================

static void rcm_init_pending_response(ResponsePkt *response){
	response->connection = NULL;
	response->data_len = 0;
}

ActiveClient *rcm_create_active_client( GSocketConnection	*connection)
{
    TRACE_FUNCTION;
    ActiveClient *c_connection = malloc(sizeof(ActiveClient));
    c_connection->mac_address = NULL;
    c_connection->connection = connection;
    c_connection->remote_client_apps = NULL;
    c_connection->authorized_devices = NULL;

    return c_connection;
}

KnownDevice *rcm_create_known_device( struct btd_adapter	*adapter,
								  struct btd_device 	*device,
								  uint8_t				*value,
								  uint8_t				 value_len){
	TRACE_FUNCTION;
	KnownDevice *known_dev = malloc(sizeof(KnownDevice));
	known_dev->device = device;
	known_dev->adv_reply = malloc(value_len);
	memcpy(known_dev->adv_reply, value, value_len);
	known_dev->adv_size = value_len;
	known_dev->device_connected = false;

	known_devices_list = g_slist_append(known_devices_list, known_dev);
	DBG("RCM: device = %p added to known_devices_list\n", device);

	return known_dev;
}

void init_userdata(UserData *data){
	data->addr = NULL;
	data->connection = NULL;
	data->stop_flag = true;
	data->payload = NULL;
	data->dev_authorized = false;
	data->filters = NULL;
	data->appid = NULL;
}

ConnectedDeviceData *rcm_create_connected_device_data( struct btd_adapter	*adapter,
												   struct btd_device	*device,
												   GSocketConnection	*connection,
												   bool					 cache_updated,
												   bool					 is_remote){
    TRACE_FUNCTION;
	ConnectedDeviceData *connected_dev_data = rcm_get_device_in_connected_device_list(device);
	if(connected_dev_data == NULL)
	{
		DBG("RCM: create new connected_device_data!\n");
		ConnectedDeviceData *connected_dev_data = malloc(sizeof(ConnectedDeviceData));
		connected_dev_data->adapter = adapter;
		connected_dev_data->device = device;
		connected_dev_data->remote_connected = is_remote;
		connected_dev_data->client_list = NULL;

		ActiveClient *active_client = rcm_get_client_by_connection_id(connection);
		active_client->has_cache_info = cache_updated;
		connected_dev_data->client_list = g_slist_append(connected_dev_data->client_list, active_client);

		connected_device_list = g_slist_append(connected_device_list, connected_dev_data);
	}
	return connected_dev_data;
}

void add_new_subscriber(GSocketConnection		*connection,
						uint16_t 				 handle,
						bdaddr_t				 bdaddr)
{
	TRACE_FUNCTION;
	// create new subscription
	NotificationSubscribers *subscr = (NotificationSubscribers *)malloc(sizeof(NotificationSubscribers));
	DeviceSubscription *dev = (DeviceSubscription *)malloc(sizeof(DeviceSubscription));

	memcpy(&dev->bdaddr, &bdaddr, 6);
	dev->handle[0] = handle;
	dev->n_handles = 1;
	subscr->subscr = dev;
	subscr->connection = connection;

	rcm_print_fd(connection, __func__);
	notification_subscribers = g_slist_append(notification_subscribers, subscr);
}

void update_subscribers(GSocketConnection		*connection,
						uint16_t 				 handle,
						bdaddr_t				 peer_addr)
{
	TRACE_FUNCTION;
	rcm_print_fd(connection, __func__);

	// check whether this client is already subscribed on a notification
	// Looking per connection because it is unique.
	// Multiple clients may be subscribed to the same device notification.
	GSList *list = NULL;
	list = g_slist_find_custom(notification_subscribers, connection, rcm_cmp_notification_subscriber);
	if(!list)
		add_new_subscriber(connection, handle, peer_addr);
	else{
		NotificationSubscribers *client_sbscr = list->data;
		gboolean already_subscribed = FALSE;
		if(rcm_compare_bdaddr(client_sbscr->subscr->bdaddr, peer_addr)){
			for(int j = 0; j < client_sbscr->subscr->n_handles; j++){
				if(client_sbscr->subscr->handle[j] == handle){
					already_subscribed = TRUE;
					break;
				}
			}
			if(!already_subscribed){
				if(client_sbscr->subscr->n_handles < 20){
					client_sbscr->subscr->handle[client_sbscr->subscr->n_handles] = handle;
					client_sbscr->subscr->n_handles++;
				}
			}
		}
	}
}

RemoteClientApplication *rcm_create_remote_client_app( GSocketConnection	*connection,
									char				*app_id,
									uint8_t				 appid_len)
{
    TRACE_FUNCTION;
    ActiveClient *active_client;
    active_client = rcm_get_client_by_connection_id(connection);
    RemoteClientApplication *remote_client_application = malloc(sizeof(RemoteClientApplication));

    char *app_str = malloc(appid_len);
    app_str = app_id;

    remote_client_application->app_id = app_str;
    remote_client_application->nb_advertisements = 0;
    remote_client_application->pending_reply_codes = 0;
    remote_client_application->uuids = NULL;

    active_client->remote_client_apps = g_slist_append(active_client->remote_client_apps, remote_client_application);

	return remote_client_application;
}

void rcm_make_active_clients_gvariant( ActiveClient	*connection,
								   gpointer			 user_data)
{
    TRACE_FUNCTION;

	GVariantBuilder *g_var_builder = user_data;
	GSocketAddress *sockaddr = g_socket_connection_get_remote_address(connection->connection, NULL);
	GInetAddress *addr = g_inet_socket_address_get_address(G_INET_SOCKET_ADDRESS(sockaddr));

	gchar * string = g_strdup_printf ("%s,%s", connection->mac_address, g_inet_address_to_string(addr));
	g_variant_builder_add (g_var_builder, "s", string);
	g_free(string);
}

// ============================================================================
// Clear memory
// ============================================================================

static void rcm_clear_remote_client(RemoteClientApplication *remote_client_application){
	if(!remote_client_application->uuids)
		g_slist_free_full(remote_client_application->uuids, g_free);
	// TODO: else : forgotten free for GSList!!!
	g_free(remote_client_application);
}

static void rcm_clear_autorized_devices(ConfigEntry *entry){
	g_free(entry->dev_address);
	g_free(entry->dev_name);
	g_free(entry);
}

static void rcm_clear_active_client(ActiveClient *c_connection){
	TRACE_FUNCTION;
	g_slist_foreach(c_connection->remote_client_apps, (GFunc)rcm_clear_remote_client, NULL);
	g_slist_foreach(c_connection->authorized_devices, (GFunc)rcm_clear_autorized_devices, NULL);

}

static void rcm_clear_known_device(KnownDevice *known_dev){
	TRACE_FUNCTION;
	free(known_dev->adv_reply);
	free(known_dev);
}

static void rcm_clear_connected_device_data(ConnectedDeviceData *connected_dev_data){
	TRACE_FUNCTION;

//	if(connected_dev_data->client_list)
//		g_slist_foreach(connected_dev_data->client_list, (GFunc)rcm_clear_active_client, NULL);
	free(connected_dev_data->connection_reply);
	free(connected_dev_data);
}

void remove_subscriber(GSocketConnection		*connection,
					   uint16_t 				 handle,
					   bdaddr_t				 	 peer_addr)
{
	GSList *list = NULL;
	list = g_slist_find_custom(notification_subscribers, connection, rcm_cmp_notification_subscriber);
	if(list)
	{
		NotificationSubscribers *client_sbscr = list->data;
		gboolean found = FALSE;
		if(rcm_compare_bdaddr(client_sbscr->subscr->bdaddr, peer_addr)){
			for(int j = 0; j < client_sbscr->subscr->n_handles; j++){
				if(client_sbscr->subscr->handle[j] == handle && !found){
					// remove handle
					//client_sbscr->subscr->handle[j] = 0;
					//found = TRUE;
					// change n_handles
					// client_sbscr->subscr->n_handles--;
					// if no more handles ->
					//free(client_sbscr->subscr);
					//notification_suscribers = g_slist_remove(notification_suscribers, client_sbscr);
					// free(&client_sbscr->subscr);
					// free(client_sbscr);
				}
			}
		}
	}
}

static GSList * rcm_remove_active_client( GSocketConnection	*connection){
    TRACE_FUNCTION;
	ActiveClient *conn;
	conn = rcm_get_client_by_connection_id(connection);
	if(conn)
	{
		rcm_clear_active_client(conn);
		active_clients = g_slist_remove(active_clients, conn);
		free(conn);
		DBG("RCM: %d active connection(s) left\n", g_slist_length(active_clients));
		return active_clients;
	}
	return NULL;
}

static void rcm_clean_notification_subscribers(NotificationSubscribers *subscr)
{
	TRACE_FUNCTION;

	if(subscr){
		if(subscr->subscr != NULL)
			free(subscr->subscr);
		free(subscr);
	}
}

static void rcm_clean_write_ids(WriteId *wid)
{
	TRACE_FUNCTION;
	free(wid);
}

static void rcm_remove_client_from_connected_device( ConnectedDeviceData	*connected_dev_data,
												 GSocketConnection		*connection) {
    TRACE_FUNCTION;

    if(connected_dev_data->client_list != NULL) {
		ActiveClient *active_client = rcm_get_client_by_connection_id(connection);

		if(active_client) {
			connected_dev_data->client_list = g_slist_remove(connected_dev_data->client_list, active_client);
			//if client_list is empty, disconnect device from proxy
			if(g_slist_length(connected_dev_data->client_list) == 0) {
				rcm_disconnect_device(connected_dev_data->device);
				connected_device_list = g_slist_remove(connected_device_list, connected_dev_data);
				free(connected_dev_data);
			}
		}else{
			DBG("RCM: Corresponding connection wasn't found!\n");
			return;
		}
	}else{
		DBG("RCM: connected_dev_data->client_list is empty\n");
		return;
	}
}

static void clean_mapping_element(BTAddrMapping *item)
{
        free(&item->real_bdaddr);
        free(&item->virt_bdaddr);
        free(item);
}

// ============================================================================
// Sending functions
// ============================================================================

static void rcm_callback_send_bytes_async(	GObject      *source_object,
											GAsyncResult *res,
											gpointer      user_data){
    TRACE_FUNCTION;
    GError            * error = NULL;
    ResponsePkt *pkt = user_data;
    GOutputStream     * ostream;
    gssize num_bytes_written;

	rcm_print_fd(pkt->connection, __func__);

    ostream = g_io_stream_get_output_stream(G_IO_STREAM(pkt->connection));
    num_bytes_written = g_output_stream_write_bytes_finish(ostream, res, &error);

    DBG("num bytes written = %d for code = %s connected? %d\n", num_bytes_written, code_to_str(pkt->reply_code), g_socket_connection_is_connected(pkt->connection));
    if (error)
    {
        DBG("packet has not been sent. Retransmitting... %d\n", pkt->nb_rtx);

        if(g_error_matches(error, G_IO_ERROR, G_IO_ERROR_BROKEN_PIPE))
        	g_printf("%s\n", error->message);

        if(pkt->nb_rtx < NB_RTX && g_socket_connection_is_connected(pkt->connection))
        {
        	pkt->nb_rtx++;
        	rcm_send_bytes_async(pkt->connection, pkt, NULL);
        	return;
        }
    }

    free(pkt->data_to_send);
	g_free(pkt);

    gpointer data = g_async_queue_try_pop(output_queue);
    if(!data)
    {
    	DBG("Queue is empty length = %d\n", g_async_queue_length(output_queue));
    	can_send = TRUE;
    	return;
    }

    ResponsePkt *next_pkt = data;

    DBG("Sending next packet: stream has pending? %d\n", g_output_stream_has_pending(ostream));
    if (g_socket_connection_is_connected(next_pkt->connection))
    {
    	rcm_send_bytes_async(next_pkt->connection, data, NULL);

        // Send to proxy_vis
    	guint16 port = rcm_get_connection_port(next_pkt->connection);
    	GSocketAddress *socket_addr = g_socket_connection_get_remote_address(next_pkt->connection, NULL);
    	GInetAddress *src_addr = g_inet_socket_address_get_address(G_INET_SOCKET_ADDRESS(socket_addr));
    	guint16 src_port = g_inet_socket_address_get_port(G_INET_SOCKET_ADDRESS(socket_addr));
    	gchar *src_addr_str = g_inet_address_to_string(src_addr);

    	GVariant *signal_data;
    	gchar *string1 = g_strdup_printf ("%s", code_to_str(next_pkt->reply_code));
    	gchar *string2 = g_strdup_printf ("%s:%d", src_addr_str, src_port);
    	signal_data = g_variant_new ("(ss)", string1, string2);
    	rcm_gdbus_send_signal("SendReply", signal_data);

    	g_free(src_addr_str);
    	g_free(string1);
    	g_free(string2);
    }
    else
    {
    	DBG("Not connected\n");
        free(next_pkt->data_to_send);
        g_free(next_pkt);
    }
}

static void rcm_send_bytes_async( GSocketConnection		*connection,
							  gpointer				 data,
							  GAsyncReadyCallback	 callback // Pass NULL to use the default callback 'rcm_callback_send_bytes_async' (see common.c)
							 ){
    TRACE_FUNCTION;
	rcm_print_fd(connection, __func__);

    GOutputStream * ostream = g_io_stream_get_output_stream(G_IO_STREAM(connection));
    DBG("Has pending? %d\n", g_output_stream_has_pending(ostream));

    can_send = FALSE;
    ResponsePkt *pkt = data;
    print_hex(pkt->data_to_send, pkt->data_len);
	rcm_print_fd(connection, __func__);

    g_output_stream_write_async(ostream,
    							pkt->data_to_send, pkt->data_len,
								0,
								NULL,
								callback ? callback : rcm_callback_send_bytes_async,
								data);
	rcm_print_fd(connection, __func__);
}

static void rcm_send_packet( GSocketConnection	*connection,
						 DataPayload *payload)
{
	TRACE_FUNCTION;

	//HUI
	DBG("RCM: Send packet to %s: %d, connection pointer is %p, code = %s\n",
			rcm_get_connection_addr(connection),
			rcm_get_connection_port(connection),
			connection,
			code_to_str(payload->reply_code));

	uint8_t *message = malloc(payload->data_len + 1);
	size_t length = 0;

	message[length] = payload->data_len;
	length += 1;

	memcpy(&message[length], payload->data, payload->data_len);
	length += payload->data_len;

	ResponsePkt *pkt = malloc(sizeof(ResponsePkt));
	rcm_init_pending_response(pkt);
	pkt->connection = connection;
	pkt->data_len = length;
	guint16 p = rcm_get_connection_port(connection);
	pkt->port = p;
	pkt->reply_code = payload->reply_code;
	pkt->data_to_send = malloc(length);
	memcpy(pkt->data_to_send, message, length);
	pkt->nb_rtx = 0;

	g_async_queue_push(output_queue, pkt);
	DBG("RCM push in the queue, length = %d\n", g_async_queue_length(output_queue));

	// Wake up the gio loop
    GOutputStream * ostream = g_io_stream_get_output_stream(G_IO_STREAM(connection));

	if(g_async_queue_length(output_queue) == 1 && !g_output_stream_has_pending(ostream) && can_send)
	{
		if (g_socket_connection_is_connected(connection))
		{
			gpointer data = g_async_queue_try_pop(output_queue);
			if(!data)
			{
				DBG("Should never get here: queue length = %d\n", g_async_queue_length(output_queue));
				return;
			}

			ResponsePkt *pkt = data;

			if (g_socket_connection_is_connected(pkt->connection))
			{
				rcm_print_fd(connection, __func__);
				rcm_print_fd(pkt->connection, __func__);
				rcm_send_bytes_async(pkt->connection, data, NULL);
			}
			else
			{
				DBG("Not connected\n");
			    free(pkt->data_to_send);
			    g_free(pkt);
			}

			// Send info to the proxy_vis
			guint16 port = rcm_get_connection_port(connection);
			GSocketAddress *socket_addr = g_socket_connection_get_remote_address(connection, NULL);
			GInetAddress *src_addr = g_inet_socket_address_get_address(G_INET_SOCKET_ADDRESS(socket_addr));
			guint16 src_port = g_inet_socket_address_get_port(G_INET_SOCKET_ADDRESS(socket_addr));
			gchar *src_addr_str = g_inet_address_to_string(src_addr);

			GVariant *signal_data;
			gchar *string1 = g_strdup_printf ("%s", code_to_str(payload->reply_code));
			gchar *string2 = g_strdup_printf ("%s:%d", src_addr_str, src_port);
			signal_data = g_variant_new ("(ss)", string1, string2);
			rcm_gdbus_send_signal("SendReply", signal_data);

			g_free(src_addr_str);
			g_free(string1);
			g_free(string2);
		}
		else
		{
			DBG("Not connected!\n");
		    free(pkt->data_to_send);
		    g_free(pkt);
		}
	}

//	free(message);
	return;
}

static void rcm_send_known_devices(KnownDevice *known_dev, UserData	*data){
	TRACE_FUNCTION;

	gchar addr_str[18] = {0};
	ba2str(&(known_dev->device->bdaddr), addr_str);
	ActiveClient *conn = rcm_get_client_by_connection_id(data->connection);
	GSList * found_el = g_slist_find_custom(conn->authorized_devices, addr_str, rcm_gdbus_find_filter_element);
	gboolean match = FALSE;
	if(found_el)
	{
		RemoteClientApplication *remote_client_application = rcm_get_remote_app_by_app_id(data->connection, data->appid);
		if(remote_client_application->uuids){
			match = rcm_is_discovery_filter_match(remote_client_application->uuids, known_dev->device->uuids);
		}
		if(match || !remote_client_application->uuids){
			DBG("Sending a known device: %s\n", addr_str);
			gboolean in_use = false;
			size_t data_size = 0;
			uint8_t *buffer_reply = malloc(known_dev->adv_size + 1);//[BUFFER_REPLY_SIZE];

			memcpy(&buffer_reply[data_size], known_dev->adv_reply, known_dev->adv_size);
			data_size += known_dev->adv_size;

			buffer_reply[data_size] = in_use;
			data_size += 1;

			DataPayload *payload = malloc(sizeof(DataPayload));
			payload->reply_code = REMOTE_CMD_START_DISCOVERY;
			payload->data_len = data_size;
			payload->data = buffer_reply;
			rcm_send_packet(data->connection, payload);
			free(buffer_reply);
			free(payload);
		}
	}
}

static void rcm_send_cache_file( ActiveClient	*active_client,
						 gpointer		 user_data){
	DataPayload *payload = user_data;
	if(!active_client->has_cache_info){
		rcm_send_packet(active_client->connection, payload);
		active_client->has_cache_info = true;
	}
}

static void rcm_start_sending_cache( void	*userdata)
{
    TRACE_FUNCTION;
	sending_cache_info = true;
	struct btd_device *device = userdata;

	struct btd_adapter *adapter = device->adapter;
	char filename[PATH_MAX], local[18], peer[18];
	int fd;
	struct stat file_stat;
	char file_size[256];
	ssize_t len;

	ConnectedDeviceData *connected_dev_data = rcm_get_device_in_connected_device_list(device);
	if(!connected_dev_data){
		DBG("[RCM] No ConnectedDeviceData found...");
		return;
	}

	ba2str(&device->bdaddr, peer);
	ba2str(&adapter->bdaddr, local);

	snprintf(filename, PATH_MAX, STORAGEDIR "/%s/cache/%s", local, peer);

		fd = open(filename, O_RDONLY);
		if (fd == -1)
		{
			DBG("Error opening file --> %s", strerror(errno));
			fprintf(stderr, "Error opening file --> %s", strerror(errno));
			return;
		}
		// Get file stats
		if (fstat(fd, &file_stat) < 0)
		{
			DBG("Error fstat --> %s", strerror(errno));
			fprintf(stderr, "Error fstat --> %s", strerror(errno));
			return;
		}

		fprintf(stdout, "File Size: %d bytes\n", file_stat.st_size);
		sprintf(file_size, "%d", file_stat.st_size);

		DBG("Sending file size = %s\n", file_size);

		FILE *fp;
		uint32_t lSize;

		fp = fopen ( filename , "r" );
		if(!fp)
		{
			DBG("Error opening file --> %s", strerror(errno));
			fprintf(stderr, "Error opening file --> %s", strerror(errno));
			return;
		}
		fseek( fp , 0L , SEEK_END);
		lSize = ftell( fp );
		rewind( fp );

		// allocate memory for entire content
		char *file_buffer = calloc( 1, lSize+1 );
		if(!file_buffer)
		{
			fprintf(stderr, "Memory allocation fails --> %s", strerror(errno));
		}
		// copy the file into the buffer
		else if(1!=fread( file_buffer , lSize, 1 , fp))
		{
		  fputs("entire read fails",stderr);
		}
		else
		{

			DBG("Sending file size lSize = %d = file_size = %s\n", lSize, file_size);
			// Crafting the packet
			uint8_t *buffer_reply = malloc(REPLY_HEADER_SIZE + sizeof(lSize) + lSize);
			DataPayload *payload = malloc(sizeof(DataPayload));
			ssize_t data_size = 0;

			buffer_reply[data_size] = REMOTE_CMD_CACHE_INFO; // HEADER
			data_size += REPLY_HEADER_SIZE;

			// Size of the file
			memcpy(&buffer_reply[data_size], &lSize, sizeof(lSize));
			data_size += sizeof(lSize);

			strncpy(&buffer_reply[data_size], file_buffer, lSize+1);

			data_size += lSize;

			payload->reply_code = REMOTE_CMD_CACHE_INFO;
			payload->data_len = data_size;
			payload->data = buffer_reply;

			g_slist_foreach(connected_dev_data->client_list, (GFunc)rcm_send_cache_file, payload);

			free(buffer_reply);
			free(payload);
		}
		fclose(fp);
		free(file_buffer);
}

static void satisfy_app_code_request(RemoteClientApplication *app, gpointer user_data){
	TRACE_FUNCTION;
	UserData *data = user_data;
	DBG("RCM: app->pending_reply_codes = %d data->payload->reply_code = %d", app->pending_reply_codes, data->payload->reply_code);
	uint16_t mask = 0;
	uint8_t shift = data->payload->reply_code - 1;

	mask |= 1<<shift;
	if(data->payload->reply_code & mask){
		if(data->payload->reply_code == REMOTE_CMD_START_DISCOVERY){
			// some discovery specific checks
			data->stop_flag = false;	// don't stop discovery yet, there is an interested client
			if(!data->dev_authorized)
				return;

			if(((app->uuids && rcm_is_discovery_filter_match(app->uuids, data->filters)) ||
				!app->uuids) &&
  			   app->nb_advertisements < NB_ADV_MAX_FILTER_SET){

				rcm_send_packet(data->connection, data->payload);
				app->nb_advertisements++;
			}
		}
		else{
			rcm_send_packet(data->connection, data->payload);
		}
	}
}

static void satisfy_client_request(ActiveClient *active_client, gpointer user_data){
	TRACE_FUNCTION;
	UserData *data = user_data;

	data->connection = active_client->connection;

	if(data->addr != NULL){
		GSList * dev_auth = g_slist_find_custom(active_client->authorized_devices, data->addr, rcm_gdbus_find_filter_element);
		if(!dev_auth){
			DBG("RCM: client is not authorized to detect this device\n");
			data->dev_authorized = false;
		}
		else{
			data->dev_authorized = true;
		}
	}
	g_slist_foreach(active_client->remote_client_apps, (GFunc)satisfy_app_code_request, data);
}

static void rcm_craft_and_send_reply(ProxyReply *reply, void *user_data){
	size_t data_size = 0;
	DataPayload *payload = NULL;
	UserData *data = NULL;

	uint8_t *buffer_reply = malloc(reply->reply_size);

	switch(reply->reply_code){
	case REMOTE_CMD_START_DISCOVERY:{
		struct btd_adapter *adapter = user_data;
		buffer_reply[data_size] = reply->reply_code; // HEADER
		data_size += REPLY_HEADER_SIZE;

		buffer_reply[data_size] = reply->reply_type.dev_detected.addr_type;
		data_size += 1;

		buffer_reply[data_size] = 6; // Address length is in bdaddr_t
		data_size += 1;

		BTAddrMapping *v_addr = map_address(reply->reply_type.dev_detected.bdaddr);
		//		bdaddr_t swapped_ba;
		//		baswap(&swapped_ba, &ev->addr.bdaddr);
		//		baswap(&swapped_ba, (bdaddr_t *)v_addr->virt_bdaddr);
		//		memcpy(&buffer_reply[data_size], &swapped_ba, 6);
		g_slist_foreach(addr_mapping_list, (GFunc)rcm_print_mapping_element, NULL);
		memcpy(&buffer_reply[data_size], &v_addr->virt_bdaddr, 6);
		data_size += 6;

		buffer_reply[data_size] = reply->reply_type.dev_detected.eir_len;
		data_size += 1;

		memcpy(&buffer_reply[data_size], reply->reply_type.dev_detected.eir, reply->reply_type.dev_detected.eir_len);
		data_size += reply->reply_type.dev_detected.eir_len;

		payload = malloc(sizeof(DataPayload));
		payload->reply_code = REMOTE_CMD_START_DISCOVERY;
		payload->data_len = data_size;
		payload->data = buffer_reply;

		data = malloc(sizeof(UserData));
		init_userdata(data);
		data->payload = payload;
		data->addr = reply->reply_type.dev_detected.addr;
		data->filters = reply->reply_type.dev_detected.services;

		g_slist_foreach(active_clients, (GFunc)satisfy_client_request, data);

		// Flag didn't change = no client is waiting for discovery results
		// If we only send the known devices -> we won't need this stop flag because
		// we never actually start discovery
		if(data->stop_flag)
		{
			DBG("RCM: No client requests scanning, STOP DISCOVERY!\n");
			rcm_process_cmd_stop_discovery(default_adapter);
		}

		// Constantly update the known devices
		struct btd_device *device = btd_adapter_find_device(adapter, reply->reply_type.dev_detected.bdaddr, reply->reply_type.dev_detected.addr_type);
		KnownDevice *known_dev = rcm_get_device_in_known_device_list(device);
		if(!known_dev)
			known_dev = rcm_create_known_device(adapter, device, buffer_reply, data_size);
		else
			DBG("RCM: Device is already in known_devices_list\n");
	}
	}
	free(buffer_reply);
	free(payload);
	free(data);
}

// TODO: move to rcm_craft_and_send_reply
static void send_write_feedback(GSocketConnection *connection, uint8_t opcode, uint8_t subcode, uint16_t handle, uint8_t *bdaddr)
{
	size_t data_size = 0;
	uint8_t *buffer_reply = malloc(1 + 1 + sizeof(uint16_t) + sizeof(uint16_t) + 6);

	buffer_reply[data_size] = opcode; // HEADER
	data_size += 1;

	buffer_reply[data_size] = subcode; // subcommand
	data_size += 1;

	memcpy(&buffer_reply[data_size], bdaddr, 6);
	data_size += 6;

	DBG("%s sending dev addr:\n", __func__);
	for(int i=0; i<6; i++)
		printf("%d ", bdaddr[i]);
	printf("\n");

	memcpy(&buffer_reply[data_size], &handle, sizeof(uint16_t));
	data_size += sizeof(uint16_t);

	uint16_t val_len = 0;
	memcpy(&buffer_reply[data_size], &val_len, sizeof(uint16_t)); // subcommand
	data_size += sizeof(uint16_t);

	DataPayload *payload = malloc(sizeof(DataPayload));
	payload->reply_code = opcode;
	payload->data_len = data_size;
	payload->data = buffer_reply;
	rcm_send_packet(connection, payload);

	free(buffer_reply);
	free(payload);
}


// ============================================================================
// Commands and Callbacks processing
// ============================================================================
// TODO: move to rcm_craft_and_send_reply
void rcm_ask_client_mac(GSocketConnection * connection)
{
    TRACE_FUNCTION;
	// Craft a packet with the special code
	size_t data_size = 0;
//	uint8_t buffer_reply[SPECIAL_RQ_SIZE];
	uint8_t *buffer_reply = malloc(REPLY_HEADER_SIZE);

	buffer_reply[data_size] = REMOTE_CMD_GET_MAC;
	data_size += REPLY_HEADER_SIZE;

	// Send it to the client

	DataPayload *payload = malloc(sizeof(DataPayload));
	payload->reply_code = REMOTE_CMD_GET_MAC;
	payload->data_len = data_size;
	payload->data = buffer_reply;

	rcm_send_packet(connection, payload);
	free(buffer_reply);
	free(payload);
}

static void remote_process_cmd_set_discovery_filter( GSocketConnection	*connection,
											 char				*app_id,
											 struct btd_adapter	*adapter,
											 GSList				*uuid_list)
{
	TRACE_FUNCTION;
	RemoteClientApplication *remote_client_application = rcm_get_remote_app_by_app_id(connection, app_id);
	remote_client_application->uuids = uuid_list;
}

static void rcm_process_cmd_start_discovery( GSocketConnection	*connection,
										char				*app_id,
										struct btd_adapter	*adapter){
	TRACE_FUNCTION;
	guint16 port = rcm_get_connection_port(connection);
	char* conn_addr = rcm_get_connection_addr(connection);
	DBG("RCM: get connection address = %s, port = %d, connection pointer is %p\n", conn_addr, port, connection);

	UserData data;
	init_userdata(&data);
	data.connection = connection;
	data.appid = app_id;
	DBG("RCM: Known device list = %p\n", known_devices_list);
	g_slist_foreach(known_devices_list, (GFunc)rcm_send_known_devices, &data);

	if(!discovery_is_running)
		rcm_trigger_new_discovery(adapter);

}

static void rcm_process_cmd_stop_discovery( struct btd_adapter	*adapter)
{
    TRACE_FUNCTION;
// TODO Check whether discovery has been started by an authorized client. If not, ignore.
	if(discovery_is_running || initialization_phase)
	{
		DBusMessage *msg = NULL; //, *reply;
		DBusMessage *reply;

		msg = dbus_message_new_method_call(BLUEZ_BUS_NAME,
				adapter->path,
				BLUEZ_INTF_ADAPTER,
				"StopDiscovery");

		gboolean ok = g_dbus_send_message(dbus_connection, msg);

		discovery_is_running = false;
	}
	else
	{
		DBG("Got StopDiscovery request but the discovery is not running\n");
	}
//	dbus_message_unref(msg);
}

static void rcm_process_cmd_device_connect( GSocketConnection	*connection,
							struct btd_adapter	*adapter,
							const bdaddr_t		 bdaddr,
							uint8_t				 addr_type,
							bool				 cache_updated){
    TRACE_FUNCTION;

	struct btd_device *device = btd_adapter_find_device(adapter, &bdaddr, addr_type);
	if(device == NULL)
	{
		DBG("No Device found!!!\n");
		return;
	}

	KnownDevice *known_dev = rcm_get_device_in_known_device_list(device);

	// TODO: get this flag from btd_device
	if(!known_dev->device_connected)
	{
		char address_str[18];
		ba2str(&bdaddr, address_str);

		DBG("Calling \"Connect\" through DBus, adapter id = %d, device_path = %s\n",
				adapter->dev_id,
				device->path);

		ConnectedDeviceData *connected_dev_data = rcm_create_connected_device_data(adapter, device, connection, cache_updated, true);

		adapter_connect_ev_cb_register(rcm_cb_connection_result);

		// Start connection procedure
		DBusMessage *msg_connect = NULL;
		DBusMessage *reply;

		msg_connect = dbus_message_new_method_call(BLUEZ_BUS_NAME,
												   device->path,
												   BLUEZ_INTF_DEVICE,
												   "Connect");

		gboolean ok_connect = g_dbus_send_message(dbus_connection, msg_connect);
	}
	else if(known_dev->device_connected) {
		// add connection in connected_dev_data->client_list
		ConnectedDeviceData *connected_dev_data = rcm_get_device_in_connected_device_list(device);

		if(connected_dev_data != NULL) {
			GSList *list = g_slist_find_custom(connected_dev_data->client_list, connection, rcm_get_active_client);

			if(!list) {
				DBG("RCM: add new client in connected_device_data\n");
				ActiveClient *active_client = rcm_get_client_by_connection_id(connection);
				active_client->has_cache_info = cache_updated;
//				AskedClient *asked_client = create_asked_client(connection, cache_updated);
				connected_dev_data->client_list = g_slist_append(connected_dev_data->client_list, active_client);
			}

			display_reply_hex(connected_dev_data->connection_reply_len, connected_dev_data->connection_reply);
			DataPayload *payload = malloc(sizeof(DataPayload));
			payload->reply_code = REMOTE_CMD_CONNECT_DEVICE;
			payload->data_len = connected_dev_data->connection_reply_len;
			payload->data = connected_dev_data->connection_reply;
			rcm_send_packet(connection, payload);

			if(cache_updated == false)
				rcm_start_sending_cache(connected_dev_data->device);
		}
	}
}

static void rcm_device_detected( uint16_t		index,
		   	   	   	   	  	  	 uint16_t		length,
								 const void    *param,
								 void		   *user_data){
	TRACE_FUNCTION;

	const struct mgmt_ev_device_found *ev = param;
	struct btd_adapter *adapter = user_data;
	const uint8_t *eir;
	uint16_t eir_len;
	uint32_t flags;
	bool confirm_name;
	bool legacy;
	char addr[18];

	// For dbus signals and debugging
	struct eir_data eir_data;
	memset(&eir_data, 0, sizeof(eir_data));

	// get EIR from the packet
	if (length < sizeof(*ev)) {
		btd_error(adapter->dev_id,
				"Too short device found event (%u bytes)", length);
		eir_data_free(&eir_data);
		return;
	}

	eir_len = btohs(ev->eir_len);

	if (length != sizeof(*ev) + eir_len) {
		btd_error(adapter->dev_id,
				"Device found event size mismatch (%u != %zu)",
				length, sizeof(*ev) + eir_len);
		eir_data_free(&eir_data);
		return;
	}

	if (eir_len == 0)
	{
		DBG("EIR is NULL! \n");
		eir = NULL;
		return; // XXX
	}
	else
	{
		eir = ev->eir;
		eir_parse(&eir_data, eir, eir_len);
	}
	// Transform the device address to string
	ba2str(&ev->addr.bdaddr, addr);
	gchar *device_name;
	const gchar *empty_name = "(empty)";
	gboolean ok = is_valid_utf8(eir_data.name);
//	DBG("DEVICE NAME IS UTF8 = %d\n", ok);
	if(ok && eir_data.name != NULL)
		device_name = g_strdup(eir_data.name);
	else
		device_name = g_strdup(empty_name);

	if(initialization_phase)
	{
		// We are building the init filter here by sending the DEviceFound event
		// A list of devices will be presented to the user/administrator.
		// Some of them will be selected to be seen/known by proxy and could be exported to the remote clients
		// DBus client will call InitProxyFilter with selected devices
		// DBus server will create the init_filter list containing them
		GVariant *g = g_variant_new ("(ssqb)", device_name, addr, ev->addr.type, 0);
		rcm_gdbus_send_signal("DeviceFound", g);
		return;
	}
	else
	{
		// Here we are not in the initialization phase
		// Thus, if a detected device is not in the init_filter list, we just ignore it
		GSList * found_el = g_slist_find_custom(init_filter, &addr, rcm_gdbus_find_filter_element);
		if (found_el == NULL) return; // Don't continue if the device is not in the init filter list
	}

	// Crafting the reply (header + data)
	ProxyReply reply;
	reply.reply_code = REMOTE_CMD_START_DISCOVERY;
	reply.reply_size = REPLY_HEADER_SIZE + 1 + 1 + strlen(addr) + 1 + eir_len;

	reply.reply_type.dev_detected.eir_len = eir_len;
	reply.reply_type.dev_detected.eir = eir;
	reply.reply_type.dev_detected.addr_type = ev->addr.type;
	reply.reply_type.dev_detected.bdaddr = &ev->addr.bdaddr;
	reply.reply_type.dev_detected.addr = addr;
	reply.reply_type.dev_detected.services = eir_data.services;

	rcm_craft_and_send_reply(&reply, adapter);

	gboolean passed = TRUE; // TODO: this should be removed from the below gvariant
	GVariant *g = g_variant_new ("(ssqb)", device_name, addr, ev->addr.type, passed);
	rcm_gdbus_send_signal("DeviceFound", g);

	g_free(device_name);
}

static void rcm_trigger_new_discovery( struct btd_adapter	*adapter){
	TRACE_FUNCTION;
	DBG("Calling StartDiscovery through DBus, adapter id = %d\n", adapter->dev_id);

	DBusMessage *msg = NULL;
	DBusMessage *reply;

	msg = dbus_message_new_method_call( BLUEZ_BUS_NAME,
										adapter->path,
										BLUEZ_INTF_ADAPTER,
										"StartDiscovery");
	gboolean ok = g_dbus_send_message(dbus_connection, msg);

	discovery_started_remotely = true;
	discovery_is_running = true;
}


// NOT USED!
// This is a kind of feedback to the client when a discovery has been stopped on the proxy
// Now, it is not used.
static void rcm_cb_stop_discovery( void	*user_data){
    TRACE_FUNCTION;
	struct btd_adapter *adapter = user_data;
	// Here we should check whether the discovery has been started remotely
	// If so, send reply to the client. Otherwise (locally started discovery) : ignore.
	if(discovery_started_remotely)
	{
		discovery_started_remotely = false;

		size_t data_size = 0;
		uint8_t buffer_reply[BUFFER_REPLY_SIZE];

		buffer_reply[data_size] = REMOTE_CMD_STOP_DISCOVERY; // HEADER
		data_size = REPLY_HEADER_SIZE;

		buffer_reply[data_size] = SUCCESS;
		data_size += 1;
		discovery_is_running = false;
	}
}

static void rcm_stop_init_discovery( void	*user_data){
	TRACE_FUNCTION;
	DBG("Stop INIT Discovery! initialization_phase = %d\n", initialization_phase);
	rcm_process_cmd_stop_discovery(default_adapter);
}

static void rcm_cb_connection_result( uint16_t		 index,
							   uint16_t		 length,
							   const void	*param,
							   void			*user_data){
    TRACE_FUNCTION;

	const struct mgmt_ev_device_connected *ev = param;
	struct btd_adapter *adapter = user_data;
	char asked_device_address[18];

	struct btd_device *ev_device;
	uint8_t *eir;
	uint16_t ev_eir_len;
	char ev_device_addr[18];

	ev_eir_len = btohs(ev->eir_len);

	ba2str(&ev->addr.bdaddr, ev_device_addr);

	ev_device = btd_adapter_find_device(adapter, &ev->addr.bdaddr,
			ev->addr.type);

	if (ev_eir_len == 0)
		eir = NULL;
	else
		eir = (uint8_t *)ev->eir;

	// Crafting the reply (header + data)
	size_t eir_size = ev_eir_len;
	size_t data_size = 0;
	uint8_t *buffer_reply = malloc(REPLY_HEADER_SIZE + 1 + 1 + strlen(ev_device_addr) + eir_size);//[BUFFER_REPLY_SIZE];
	DataPayload *payload = malloc(sizeof(DataPayload));
	UserData *data = malloc(sizeof(UserData));

	buffer_reply[data_size] = REMOTE_CMD_CONNECT_DEVICE; // HEADER
	data_size += REPLY_HEADER_SIZE;

	buffer_reply[data_size] = ev->addr.type;
	data_size += 1;
/*
	buffer_reply[data_size] = strlen(ev_device_addr);
	data_size += 1;

	memcpy(&buffer_reply[data_size], ev_device_addr, strlen(ev_device_addr));
	data_size += strlen(ev_device_addr);
*/
	buffer_reply[data_size] = 6; // Address length is in bdaddr_t
	data_size += 1;

//	bdaddr_t swapped_ba;
//	baswap(&swapped_ba, &ev->addr.bdaddr);

    GSList *l = g_slist_find_custom(addr_mapping_list, &ev->addr.bdaddr, find_mapping_real);
    if(!l)
    {
    	printf("Mapped element not found\n");
    	return;
    }
    BTAddrMapping *v_addr = (BTAddrMapping *)l->data;
//	memcpy(&buffer_reply[data_size], &ev->addr.bdaddr, 6);
    memcpy(&buffer_reply[data_size], &v_addr->virt_bdaddr, 6);
	data_size += 6;

	buffer_reply[data_size] = eir_size;
	data_size += 1;

	memcpy(&buffer_reply[data_size], eir, eir_size);
	data_size += eir_size;

	//HUI: only 1st client who connects with this device will call this function
	ConnectedDeviceData *connected_dev_data = rcm_get_device_in_connected_device_list(ev_device);
	if(connected_dev_data)
	{
		connected_dev_data->connection_reply = malloc(data_size);
		memcpy(connected_dev_data->connection_reply, buffer_reply, data_size);
		connected_dev_data->connection_reply_len = data_size;
		g_printf("---------------------------- Inside connection result, buffer_reply: \n");
		display_reply_hex(data_size, buffer_reply);
		g_printf("connection_reply (should be a copy of buffer_reply): \n");
		display_reply_hex(connected_dev_data->connection_reply_len, connected_dev_data->connection_reply);
		g_printf("----------------------------\n");

		payload->reply_code = REMOTE_CMD_CONNECT_DEVICE;
		payload->data_len = data_size;
		payload->data = buffer_reply;

		init_userdata(data);
		data->payload = payload;

		g_slist_foreach(connected_dev_data->client_list, (GFunc)satisfy_client_request, data);

		// Send gdbus signal
		GVariant *signal_data;
		signal_data = g_variant_new ("(s)", g_strdup_printf ("%s", ev_device_addr));
		rcm_gdbus_send_signal("DeviceConnected", signal_data);
	}

	KnownDevice *known_dev = rcm_get_device_in_known_device_list(ev_device);
	if(known_dev != NULL)
	{
		known_dev->device_connected = true;
	}
	free(buffer_reply);
	free(payload);
	free(data);
}


void rcm_cb_rcv_notification(uint16_t value_handle, uint16_t value_len, const uint8_t *value){
	TRACE_FUNCTION;

	GSocketConnection *connection = NULL;
	size_t data_size = 0;
	uint8_t *buffer_reply = malloc(1 + 1 + sizeof(uint16_t) + sizeof(uint16_t) + value_len + 6);

	buffer_reply[data_size] = REMOTE_CHAR_WRITE; // HEADER
	data_size += 1;

	buffer_reply[data_size] = REMOTE_START_STOP_NOTIF; // subcommand
	data_size += 1;

	// get connection by handle:
	GSList *list = NULL;
	list = g_slist_find_custom(notification_subscribers, GUINT_TO_POINTER(value_handle), rcm_get_subscriber_by_handle);
	if(list){
		NotificationSubscribers *client = list->data;
	    GSList *l = g_slist_find_custom(addr_mapping_list, &client->subscr->bdaddr, find_mapping_real);
	    if(!l)
	    {
	    	printf("Mapped element not found\n");
	    	return;
	    }
	    BTAddrMapping *v_addr = (BTAddrMapping *)l->data;

		memcpy(&buffer_reply[data_size], &v_addr->virt_bdaddr, 6);
		data_size += 6;
		connection = client->connection;
	}
	else if(!list){
		DBG("Subscriber not found\n");
		free(buffer_reply);
		return;
	}

	rcm_print_fd(connection, __func__);

	memcpy(&buffer_reply[data_size], &value_handle, sizeof(uint16_t));
	data_size += sizeof(uint16_t);

	memcpy(&buffer_reply[data_size], &value_len, sizeof(uint16_t));
	data_size += sizeof(uint16_t);

	memcpy(&buffer_reply[data_size], value, value_len);
	data_size += value_len;

	printf("Notification value:\n");
	for(int i=0; i<value_len; i++)
		printf("%02x ", value[i]);
	printf("\n");

	rcm_print_fd(connection, __func__);

	DataPayload *payload = malloc(sizeof(DataPayload));
	payload->reply_code = REMOTE_CHAR_WRITE;
	payload->data_len = data_size;
	payload->data = buffer_reply;
	rcm_send_packet(connection, payload);
}

void rcm_cb_start_write_char(unsigned int id, uint16_t handle){
    TRACE_FUNCTION;

    DBG("Add element id %d for handle %02x\n", id, handle);
	GSList *list = g_slist_find_custom(write_ids, GUINT_TO_POINTER(handle), rcm_get_write_id);
	if(list){
		WriteId *wid = list->data;
		wid->id = id;
	}
	else DBG("Element not found...\n");
}

void rcm_cb_write_char_result(unsigned int id){
    TRACE_FUNCTION;

	GSList *list = g_slist_find_custom(write_ids, GUINT_TO_POINTER(id), rcm_get_write_handle);
	if(list){
		WriteId *wid = list->data;
		rcm_print_fd(wid->connection, __func__);
		send_write_feedback(wid->connection, REMOTE_CHAR_WRITE, REMOTE_CHAR_WRITE, wid->handle, wid->bdaddr);
		DBG("Looking for id = %d handle = %02x element found\n", wid->id, wid->handle);

		// remove this element now
		write_ids = g_slist_remove(write_ids, wid);
//		free(wid->bdaddr);
		free(wid);
	}
	else DBG("Element for id %d not found\n", id);
}

static void rcm_process_cmd_write_characteristic( GSocketConnection		*connection,
								  char					*char_path,
								  uint8_t			 	 value_len,
								  const uint8_t			*value,
								  struct btd_adapter 	*adapter,
								  uint16_t				 handle,
								  uint8_t 				 opcode,
								  bdaddr_t 			 	 peer_addr,
								  uint8_t				*peer_virt_addr){
    TRACE_FUNCTION;
//	display_reply_hex(value_len, value);

	// char_path may be different on different machines
	// At least the hci may not be the same

    char *adapter_path = adapter->path;
    int adapter_path_len = strlen(adapter_path);
	int char_path_len = strlen(char_path);
	int complete_path_len = adapter_path_len + char_path_len;

	char complete_path[complete_path_len]; // complete path to the characteristic
	strcpy(complete_path, adapter_path);
	strcat(complete_path, char_path);
	DBG("Complete path = %s, length = %d, dev_path_len = %d, char_path_len = %d\n",
			complete_path, strlen(complete_path), adapter_path_len, char_path_len);

	// TODO generate a DBus message to write a characteristic value
	DBusMessage *msg = NULL;

	char intf[40];
	char cmd[20];
	if(opcode == REMOTE_START_STOP_NOTIF)
	{
        uint16_t val = *((uint16_t*)value);
		if(val == 1){
			rcm_print_fd(connection, __func__);
			update_subscribers(connection, handle, peer_addr);
			printf("StartNotify received\n");
			sprintf(cmd, "%s", "StartNotify");
			complete_path[strlen(complete_path)-1] = 'd';
			WriteId *write_id = (WriteId *) malloc(sizeof(WriteId));
			write_id->handle = handle;
			write_id->id = 0;
			write_id->connection = connection;
			memcpy(write_id->bdaddr, peer_virt_addr, 6);
			write_ids = g_slist_append(write_ids, write_id);
			rcm_print_fd(connection, __func__);
			rcm_print_fd(write_id->connection, __func__);
		}
		else{
			remove_subscriber(connection, handle, peer_addr);
			printf("StopNotify received\n");
			sprintf(cmd, "%s", "StopNotify");
		}
		sprintf(intf, "%s", BLUEZ_INTF_CHAR);
	}
	else if(opcode == REMOTE_DESC_WRITE)
	{
		printf("Descriptor WriteValue received\n");
		sprintf(cmd, "%s", "WriteValue");
		sprintf(intf, "%s", BLUEZ_INTF_DESC);
	}
	else{ // If the command is a standard REMOTE_CHAR_WRITE
		printf("Characteristic WriteValue received handle %02x\n", handle);
		sprintf(cmd, "%s", "WriteValue");
		sprintf(intf, "%s", BLUEZ_INTF_CHAR);
		complete_path[strlen(complete_path)-1] -= 1 ;
		WriteId *write_id = (WriteId *) malloc(sizeof(WriteId));
		write_id->handle = handle;
		write_id->id = 0;
		write_id->connection = connection;
		memcpy(write_id->bdaddr, peer_virt_addr, 6);
		write_ids = g_slist_append(write_ids, write_id);
	}
	DBG("New Complete path = %s\n", complete_path);

	msg = dbus_message_new_method_call(BLUEZ_BUS_NAME,
									   complete_path,
									   ///org/bluez/hci0/dev_F8_1D_78_60_3D_D9/service0009/char000a
									   intf,
									   cmd);

	// Append an argument to the message
	if(opcode != REMOTE_START_STOP_NOTIF){
		DBusMessageIter iter, array, dict;
		dbus_message_iter_init_append(msg, &iter);
		dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "y", &array);

		if(!dbus_message_iter_append_fixed_array(&array, DBUS_TYPE_BYTE,
				&value, value_len))
		{
			DBG("Out of memory!\n");
		}
		dbus_message_iter_close_container(&iter, &array);

		dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
				DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
				DBUS_TYPE_STRING_AS_STRING
				DBUS_TYPE_VARIANT_AS_STRING
				DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
				&dict);

		dbus_message_iter_close_container(&iter, &dict);
	}
	gboolean ok = g_dbus_send_message(dbus_connection, msg);

	DBG("DBus message sent\n");
}


static void rcm_disconnect_device( struct btd_device	*device){
    TRACE_FUNCTION;
	KnownDevice *known_dev = rcm_get_device_in_known_device_list(device);
	if(known_dev->device_connected)
	{
		DBusMessage *msg = NULL;
		DBusMessage *reply;

		msg = dbus_message_new_method_call(BLUEZ_BUS_NAME,
				device->path,
				BLUEZ_INTF_DEVICE,
				"Disconnect");
//		DBG("DBus message pointer = %p", msg);
		gboolean ok = g_dbus_send_message(dbus_connection, msg);
//		DBG("DBus message sent = %d", ok);

		known_dev->device_connected = false;

		// Send gdbus signal
		GVariant *signal_data;
		gchar addr[18];
		ba2str(&device->bdaddr, addr);
		signal_data = g_variant_new ("(s)", g_strdup_printf ("%s", addr));
		rcm_gdbus_send_signal("DeviceDisconnected", signal_data);
	}
	else
	{
		DBG("Got Disconnect request but the device is not connected\n");
	}
}

void rcm_process_mac_address( char *mac,
						  char *mac_str,
						  GSocketConnection * connection,
						  gboolean *authorized){
    TRACE_FUNCTION;

	tohex(mac, 6, mac_str, 18);
	DBG("mac_str = %s\n", mac_str);

	ActiveClient *c_connection = rcm_get_client_by_mac_addr(mac_str);
	if(!c_connection){
		ActiveClient *conn = rcm_get_client_by_connection_id(connection);
		if(!conn) return;
		// TODO: Add here some cheking to manage authorized mac addresses only
		conn->mac_address = g_strdup(mac_str);
		if(conn->authorized_devices != NULL)
			(*authorized) = TRUE;
		DBG("c_connection->mac_address %s, c_connection %p\n", conn->mac_address, conn);
	}
	else{
		if(c_connection->authorized_devices != NULL)
			(*authorized) = TRUE;

		if(c_connection->connection != connection){
			c_connection->connection = connection;
		}
	}
}

char * rcm_process_appid( uint8_t appid_len,
					  const uint8_t *appid_raw,
					  GSocketConnection * connection)
{
    TRACE_FUNCTION;

	char *app_id;
	app_id = uint8_to_utf8(appid_raw, appid_len, appid_len);
	DBG("RCM: app_id = %s\n", app_id);

	RemoteClientApplication *remote_client_application = rcm_get_remote_app_by_app_id(connection, app_id);
	if(!remote_client_application)
		remote_client_application = rcm_create_remote_client_app(connection, app_id, appid_len);
	return app_id;
}

void rcm_generate_dev_path(char *dev_path, bdaddr_t bda){
	sprintf(dev_path, "/dev_%2.2X_%2.2X_%2.2X_%2.2X_%2.2X_%2.2X/", bda.b[5], bda.b[4], bda.b[3], bda.b[2], bda.b[1], bda.b[0]);
	printf("dev_path = %s", dev_path);
}

static ssize_t rcm_parse_header( RCMHeader *pkt_header,
							  uint8_t *buffer,
							  ssize_t byte_iterator,
							  gchar *src_addr_str,
							  GSocketConnection *connection,
							  gboolean *authorized){
	TRACE_FUNCTION;
// Format: [pkt_len][mac_addr][appid_len][appid][opcode]
	pkt_header->pkt_len = buffer[byte_iterator];
	byte_iterator += 1;

	display_reply_hex(pkt_header->pkt_len, &buffer[byte_iterator]);

	// Extract and process client MAC address
	char * mac = &buffer[byte_iterator];
	byte_iterator += 6;
	rcm_process_mac_address(mac, pkt_header->mac_addr, connection, authorized);

	// Extract and process application id
	pkt_header->appid_len = buffer[byte_iterator];
	byte_iterator += 1;

	if(pkt_header->appid_len == 0)
		return byte_iterator;

	const uint8_t *app_raw = &buffer[byte_iterator];
	byte_iterator += pkt_header->appid_len;
	// TODO: free forgotten, this appid is allocated with strdup and should be freed once no more needed!!!
	pkt_header->appid = rcm_process_appid(pkt_header->appid_len, app_raw, connection);

	// Extract opcode
	pkt_header->opcode = buffer[byte_iterator];
	byte_iterator += 1;

	return byte_iterator;
}

static gboolean rcm_cb_socket_read( GIOChannel    *channel,
							   GIOCondition   condition,
							   gpointer       user_data){
    TRACE_FUNCTION;
    GSocketConnection * connection = G_SOCKET_CONNECTION(user_data);
    GError * error = NULL;

    guint16 port = rcm_get_connection_port(connection);
    GSocketAddress *socket_addr = g_socket_connection_get_remote_address(connection, NULL);
    GInetAddress *src_addr = g_inet_socket_address_get_address(G_INET_SOCKET_ADDRESS(socket_addr));
    guint16 src_port = g_inet_socket_address_get_port(G_INET_SOCKET_ADDRESS(socket_addr));
    GVariant *g = NULL;

    if (condition & G_IO_HUP){
        DBG("The client has disconnected!\n");
        return FALSE; // The client has disconnected abruptly, remove this GSource
    }

    gchar buffer[BUFSIZ];
    gssize buffer_len = 0;

    GInputStream * istream = g_io_stream_get_input_stream(G_IO_STREAM(connection));
    buffer_len = g_input_stream_read(istream, buffer, BUFSIZ, NULL, &error);

    switch (buffer_len){
    case -1:{
    	g_error("Error reading: %s\n", error->message);
    	g_object_unref(connection);
    	return FALSE;
    }
    case 0:{
    	DBG("Client disconnected\n");
    	if(connected_device_list){
    		g_slist_foreach(connected_device_list, (GFunc)rcm_remove_client_from_connected_device, connection);
    	}
    	if(notification_subscribers){
    		g_slist_free_full(notification_subscribers, (GDestroyNotify)rcm_clean_notification_subscribers);
    		notification_subscribers = NULL;
    	}
    	if(write_ids){
    		g_slist_free_full(write_ids, (GDestroyNotify)rcm_clean_write_ids);
    		write_ids = NULL;
    	}

    	active_clients = rcm_remove_active_client(connection);

    	GVariant *signal_data;
    	gchar *src_addr_str = g_inet_address_to_string(src_addr);
    	signal_data = g_variant_new ("(sq)", src_addr_str, port);
    	rcm_gdbus_send_signal("ClientDisconnected", signal_data);
    	g_free(src_addr_str);

    	GError *error = NULL;
    	g_io_stream_close(G_IO_STREAM(connection), NULL, &error);
    	if(error)
    		DBG("Error closing socket %s\n", error->message);
    	return FALSE;
    }
    default:
    	break;
    }

    if (buffer_len){
    	display_reply_hex(buffer_len, buffer);

    	gchar *src_addr_str = g_inet_address_to_string(src_addr);
		gchar *addr_port_str = g_strdup_printf ("%s:%d", src_addr_str, src_port);

		// Managing aggregated packets
    	ssize_t pkt_start_byte = 0;
    	while(pkt_start_byte < buffer_len - 1){

    		RCMHeader pkt_header;
    		gboolean authorized = FALSE;
    		ssize_t byte_iterator = rcm_parse_header(&pkt_header, buffer, pkt_start_byte, src_addr_str, connection, &authorized);

    		DBG("pkt_header.pkt_length = %d, byte_iterator = %d pkt_start_byte = %d buffer = %p\n",
    				pkt_header.pkt_len, byte_iterator, pkt_start_byte, &buffer[0]);
    		if(pkt_header.appid_len == 0){
    			GVariant *signal_data;
    			signal_data = g_variant_new ("(ss)", src_addr_str, pkt_header.mac_addr);
    			rcm_gdbus_send_signal("NewConnection", signal_data);
        		pkt_start_byte += pkt_header.pkt_len;
    			continue;
    		}

    		if(!authorized){
        		pkt_start_byte += pkt_header.pkt_len;
        		continue;
    		}
    		rcm_set_new_wait_code(connection, pkt_header.appid, pkt_header.opcode);
    		switch (pkt_header.opcode)
    		{
    		case REMOTE_CMD_SET_FILTER:
    		{
    			//create uuid_list from msg
    			guint uuid_count = buffer[byte_iterator];//the number of uuid in the msg
    			byte_iterator += 1;
    			DBG("The number of uuid is %d\n", uuid_count);

    			GSList *uuid_list = NULL;

    			for(int i = 0; i < uuid_count; i++)
    			{
    				uint8_t uuid_len = buffer[byte_iterator];
    				byte_iterator += 1;
    				const uint8_t *uuid = &buffer[byte_iterator];
    				byte_iterator += uuid_len;

    				char* uuid_str = uint8_to_utf8(uuid, uuid_len, uuid_len);
    				DBG("uuid_str = %s\n", uuid_str);
    				uuid_list = g_slist_append(uuid_list, uuid_str);
    			}

    			g = g_variant_new ("(ss)",
    					code_to_str(REMOTE_CMD_SET_FILTER),
						addr_port_str);
    			rcm_gdbus_send_signal("RcvRequest", g);

    			remote_process_cmd_set_discovery_filter(connection, pkt_header.appid, default_adapter, uuid_list);
    			break;
    		}
    		case REMOTE_CMD_START_DISCOVERY:
    		{
    			// if the app is already connected, ignore the start discovery
//    			if(!ignore_discovery(connection)){
//    				rcm_set_new_wait_code(connection, app_id, op);
    				g = g_variant_new ("(ss)", code_to_str(REMOTE_CMD_START_DISCOVERY), addr_port_str);
    				rcm_gdbus_send_signal("RcvRequest", g);

    				rcm_process_cmd_start_discovery(connection, pkt_header.appid, default_adapter);
//    			}
    			break;
    		}
    		case REMOTE_CMD_CONNECT_DEVICE:
    		{
    			// TODO: Add connect header info like PacketHeader above
    			bool is_remote = buffer[byte_iterator];
    			byte_iterator += 1;

    			bool cache_updated = buffer[byte_iterator];
    			byte_iterator += 1;

    			uint8_t addr_type = buffer[byte_iterator];
    			byte_iterator += 1;

    			uint8_t addr_len = buffer[byte_iterator];
    			byte_iterator += 1;

    			const uint8_t *addr = &buffer[byte_iterator];
    			byte_iterator += addr_len;

    			char *addr_str;
    			addr_str = uint8_to_utf8(addr, addr_len, 18);

    			bdaddr_t addr_bt;
    			str2ba(addr_str, &addr_bt);
    			bdaddr_t addr_bt_swapped;
    			baswap(&addr_bt_swapped, &addr_bt);
    			g_slist_foreach(addr_mapping_list, (GFunc)rcm_print_mapping_element, NULL);
    	        GSList *rl = g_slist_find_custom(addr_mapping_list, addr_bt_swapped.b, find_mapping_virt);
    	        if(!rl)
    	        {
    	        	printf("Mapped address not found\n");
    	        	break;
    	        }
    	        BTAddrMapping *real_addr = (BTAddrMapping *)rl->data;
    	        real_addr->connection = connection;

    			if(is_remote)
    			{
    				gchar *addr_code = g_strdup_printf ("%s\t%s", addr_str, code_to_str(REMOTE_CMD_CONNECT_DEVICE));
    				g = g_variant_new ("(ss)", addr_code, addr_port_str);
        			rcm_gdbus_send_signal("RcvRequest", g);
    				g_free(addr_code);

    				rcm_process_cmd_device_connect(connection, default_adapter, real_addr->real_bdaddr, addr_type, cache_updated);
    			}
    			else
    			{
    				//Device is already connected locally, add to connected_device_list directly
    				struct btd_device *device = btd_adapter_find_device(default_adapter, &real_addr->real_bdaddr, addr_type);
    				ConnectedDeviceData *connected_dev_data = rcm_create_connected_device_data(default_adapter, device, connection, cache_updated, false);
    			}
    			break;
    		}
    		case REMOTE_CMD_DISCONNECT_DEVICE:
    		{
    			uint8_t addr_type = buffer[byte_iterator];
    			byte_iterator += 1;

    			uint8_t addr_len = buffer[byte_iterator];
    			byte_iterator += 1;

    			const uint8_t *addr = &buffer[byte_iterator];
    			byte_iterator += addr_len;

    			char *addr_str;
    			addr_str = uint8_to_utf8(addr, addr_len, 18);

    			bdaddr_t addr_bt;
    			str2ba(addr_str, &addr_bt);
    			GSList *rl = g_slist_find_custom(addr_mapping_list, addr_bt.b, find_mapping_virt);
    			if(!rl) printf("Mapped address not found\n");
    			BTAddrMapping *real_addr = (BTAddrMapping *)rl->data;

    			struct btd_device *device = btd_adapter_find_device(default_adapter, &real_addr->real_bdaddr, addr_type);
    			ConnectedDeviceData *connected_dev_data = rcm_get_device_in_connected_device_list(device);
    			if(connected_dev_data)
    				rcm_remove_client_from_connected_device(connected_dev_data, connection);
    			break;
    		}
    		case REMOTE_CMD_STOP_DISCOVERY:
    		{
    			g = g_variant_new ("(ss)",
    					code_to_str(REMOTE_CMD_STOP_DISCOVERY),
						addr_port_str);
    			rcm_gdbus_send_signal("RcvRequest", g);

    			// Reinitialize the advertisement counter
    			RemoteClientApplication *remote_client_application = rcm_get_remote_app_by_app_id(connection, pkt_header.appid);
    			if(remote_client_application->nb_advertisements > 0)
    			{
    				remote_client_application->nb_advertisements = 0;
    			}
    			rcm_process_cmd_stop_discovery(default_adapter);

    			break;
    		}
    		case REMOTE_CHAR_WRITE:
    		{
    			uint8_t subcode = buffer[byte_iterator]; // REMOTE_DESC_WRITE or REMOTE_START_STOP_NOTIF
    			byte_iterator += 1;

    			bdaddr_t bdaddr;
    			memcpy(&bdaddr.b, &buffer[byte_iterator], 6);
    			byte_iterator += 6;

//    			bdaddr_t addr_bt_swapped;
//    			baswap(&addr_bt_swapped, &bdaddr);
    			g_slist_foreach(addr_mapping_list, (GFunc)rcm_print_mapping_element, NULL);

    			GSList *rl = g_slist_find_custom(addr_mapping_list, bdaddr.b, find_mapping_virt);
    	        if(!rl) printf("Mapped address not found\n");
    	        BTAddrMapping *real_addr = (BTAddrMapping *)rl->data;

    			char dev_path[24] = {0};
    			rcm_generate_dev_path(dev_path, real_addr->real_bdaddr);

    			//   		display_reply_hex(len, buffer);
    			uint8_t path_len = buffer[byte_iterator];
    			byte_iterator += 1;

    			char* char_path;
    			const uint8_t *char_path_raw = &buffer[byte_iterator];
    			byte_iterator += path_len;
    			//Transform the binary to string
    			char_path = uint8_to_utf8(char_path_raw, path_len, path_len);
    			DBG("[REMOTE_CHAR_WRITE] characteristic path = %s\n", char_path);

    			// Let's get the char value and its length
    			uint8_t value_len = buffer[byte_iterator];
    			byte_iterator += 2;//CHAR_VALUE_LEN;
    			DBG("[REMOTE_CHAR_WRITE] check the value length = %d\n", value_len);

    			uint8_t value[value_len];
    			memcpy(value, &buffer[byte_iterator], value_len);
    			byte_iterator += value_len;

    			uint16_t handle;
    			memcpy(&handle, &buffer[byte_iterator], sizeof(uint16_t));
    			byte_iterator += sizeof(uint16_t);

    			g_printf("value = ");
    			for (int i = 0; i < value_len; ++i)
    			{
    				g_printf("%02x", value[i]);
    			}
    			gchar value_str[value_len * 2 + 1];

    			for(int i=0, j=0; i<value_len; i++, j+=2)
    				sprintf(&value_str[j], "%02x", value[i]);

    			gchar *gvar_msg_str = g_strdup_printf ("%s characteristic path: %s, value: %s", code_to_str(REMOTE_CHAR_WRITE), char_path, value_str);
    			g = g_variant_new ("(ss)",gvar_msg_str, addr_port_str);
    			rcm_gdbus_send_signal("RcvRequest", g);
    			g_free(gvar_msg_str);

    			char complete_path[85] = {0};
    			sprintf(complete_path, "%s%s", dev_path, char_path);

    			rcm_process_cmd_write_characteristic(connection, complete_path, value_len, value, default_adapter, handle, subcode, real_addr->real_bdaddr, real_addr->virt_bdaddr);
    			break;
    		}
    		case REMOTE_CMD_GET_MAC:
    		{
    			// For the moment, we never gets here because the function will break on appid_len == 0
    			break;
    		}
    		default:
    			DBG("Unknown command %d\n", pkt_header.opcode);
    			break;
    		}

    		pkt_start_byte += pkt_header.pkt_len;
    	}
    	g_free(addr_port_str);
    	g_free(src_addr_str);
    }
	return TRUE;
}

void rcm_authorize_device(gchar *mac, ConfigEntry *filter_entry)
{
	TRACE_FUNCTION;

	ActiveClient *connection = rcm_get_client_by_mac_addr(mac);
	if(!connection)
		return;

	connection->authorized_devices = g_slist_append(connection->authorized_devices, filter_entry);
}

// ============================================================================
// Sockets/Connections
// ============================================================================

// This function will get called everytime a client attempts to connect
gboolean rcm_cb_new_connection( GThreadedSocketService	*service,
						   GSocketConnection		*connection,
						   GObject          		*source_object,
						   gpointer            		 user_data)
{
    TRACE_FUNCTION;
    GError * error = NULL;

    rcm_print_connection(connection);

    GSList *found = rcm_get_active_client_ip(active_clients, connection);
    if(found) return FALSE;
    //HUI
    ActiveClient *c_connection = rcm_create_active_client(connection);
    active_clients = g_slist_append(active_clients, c_connection);

    DBG("connected_device_list length = %d\n", g_slist_length(connected_device_list));

    g_slist_foreach(active_clients, (GFunc)rcm_print_active_client, NULL);

    // Install watch
    g_object_ref(connection); // ADDED
    GSocket * socket = g_socket_connection_get_socket(connection);

    //Disable TCP aggregation
    GError *error_opt = NULL;
    g_socket_set_option(socket, IPPROTO_TCP, TCP_NODELAY, 1, &error_opt);
    if(error_opt)
    	g_error("Cannot set TCP_NODELAY: %s", error_opt->message);

    /*
    int yes = 1;
    g_socket_set_option(socket, SOL_SOCKET, SO_KEEPALIVE, yes, &error_opt);
    if(error_opt)
    	g_error("Cannot set SO_KEEPALIVE: %s", error_opt->message);

    int idle = 1;
    g_socket_set_option(socket, IPPROTO_TCP, TCP_KEEPIDLE, idle, &error_opt);
    if(error_opt)
    	g_error("Cannot set TCP_KEEPIDLE: %s", error_opt->message);

    int interval = 1;
    g_socket_set_option(socket, IPPROTO_TCP, TCP_KEEPINTVL, interval, &error_opt);
    if(error_opt)
    	g_error("Cannot set TCP_KEEPINTVL: %s", error_opt->message);

    int maxpkt = 10;
    g_socket_set_option(socket, IPPROTO_TCP, TCP_KEEPCNT, maxpkt, &error_opt);
    if(error_opt)
    	g_error("Cannot set TCP_KEEPCNT: %s", error_opt->message);
*/
    // From here, the code is the same in the client and the server.

    gint fd = g_socket_get_fd(socket);
    GIOChannel * channel = g_io_channel_unix_new(fd);

    if (!channel)
    {
        g_error("Cannot create channel\n");
        return TRUE;
    }

    // Exchange binary data with the client
    g_io_channel_set_encoding(channel, NULL, &error);
    if (error)
    {
        g_error("Cannot set encoding: %s", error->message);
        return TRUE;
    }

    // G_IO_IN: There is data to read.
    // G_IO_OUT: Data can be written (without blocking).
    // G_IO_PRI: There is urgent data to read.
    // G_IO_ERR: Error condition.
    // G_IO_HUP: Hung up (the connection has been broken, usually for pipes and sockets).
    // G_IO_NVAL: Invalid request. The file descriptor is not open.

    // Triggered whenever the server can read data from the socket
    if (!g_io_add_watch(channel, G_IO_IN | G_IO_HUP, rcm_cb_socket_read, connection))
    {
        g_error("Cannot watch\n");
        return TRUE;
    }
/*    if (!g_io_add_watch(channel, G_IO_OUT | G_IO_HUP, callback_write, connection))
    {
        g_error("Cannot watch\n");
        return TRUE;
    }
*/
    // Get the client's MAC address
    // Authentication procedures may be run here instead
    // We use MAC address because it's easy to get and because the security part
    // is out of scope of our current work on this PoC
    rcm_ask_client_mac(connection);
    return FALSE;
}

void rcm_configure_threaded_socket(){
    TRACE_FUNCTION;
	// socket()
	GError * error = NULL;
	service = (GThreadedSocketService*)g_threaded_socket_service_new(-1);

	g_socket_listener_add_inet_port((GSocketListener *) service,
									PORT,
									NULL,
									&error);

	if (error)
	{
		DBG("Problem in g_socket_listener_add_inet_port when configuring threaded socket:\n");
		g_error(error->message);
		return;
	}

	// Listen to the 'incoming' signal
	g_signal_connect(service,
					 "run",
					 G_CALLBACK(rcm_cb_new_connection),
					 NULL);

	// Start the socket service
	g_socket_service_start((GSocketService*)service);

	// Run the main loop (it is the same as the bluez's one, so it is already run)
	DBG("Listening on port number %d\n", PORT);
}

void rcm_cb_initialize_proxy_filter( void	*user_data){
	rcm_trigger_new_discovery(default_adapter);
}

void rcm_configure_socket(){
    TRACE_FUNCTION;
	rcm_configure_threaded_socket();
}

// Called so many times as you have Bluetooth adapters (once per adapter)
// Check the number of adapters with hciconfig
static int rcm_proxy_probe( struct btd_adapter	*adapter)
{
    TRACE_FUNCTION;
	default_adapter = adapter;

#if !GLIB_CHECK_VERSION(2, 35, 0)
	g_type_init ();
#endif
	//		loop = g_main_loop_new(NULL, FALSE);
	//		g_main_loop_run(loop);
	return 0;
}

static void rcm_proxy_remove( struct btd_adapter	*adapter)
{
    TRACE_FUNCTION;
//	g_main_loop_unref(loop);
}

static struct btd_adapter_driver rcm_proxy = {
	.name = "Remote Connection Manager - Proxy part (RCM-p)",
	.probe = rcm_proxy_probe,
	.remove = rcm_proxy_remove,
};

// Called only once at the plugin run
static int rcm_proxy_init(void)
{
    TRACE_FUNCTION;

	btd_register_adapter_driver(&rcm_proxy);

//	configure_socket();
// moved to open_the door function in order to call it once the proxy is initialized
// (manually for the moment but should be loaded from file in future)
//	rcm_configure_threaded_socket();

	rcm_gdbus_config();

	adapter_device_found_cb_register(rcm_device_detected);
	adapter_stop_discovery_cb_register(rcm_cb_stop_discovery);
	device_connection_completed_cb_register(rcm_start_sending_cache);
	proxy_stop_init_discovery_cb_register(rcm_stop_init_discovery);
	proxy_init_cb_register(rcm_cb_initialize_proxy_filter); // Call StartDiscovery
	get_active_clients_cb_register(rcm_cb_get_active_clients);
//	proxy_disconnect_cb_register(disconnect_ble_devices);
	notify_cb_register(rcm_cb_rcv_notification);
	start_write_cb_register(rcm_cb_start_write_char);
	write_result_cb_register(rcm_cb_write_char_result);
	// Initialize the queue
	g_async_queue_ref(output_queue);
	output_queue = g_async_queue_new();

	rcm_gdbus_run_server();

	return 0;
}

//HUI
static void rcm_free_allocated_memory(void)
{
    TRACE_FUNCTION;
	DBG("RCM: proxy closed, free allocated memory");
	if(known_devices_list)
	{
		g_slist_free_full(known_devices_list, (GDestroyNotify)rcm_clear_known_device);
		known_devices_list = NULL;
	}

	if(connected_device_list)
	{
		g_slist_free_full(connected_device_list, (GDestroyNotify)rcm_clear_connected_device_data);
		connected_device_list = NULL;
	}
	if(active_clients)
	{
		g_slist_free_full(active_clients, (GDestroyNotify)rcm_clear_active_client);
		active_clients = NULL;
	}
	if(notification_subscribers)
	{
		g_slist_free_full(notification_subscribers, (GDestroyNotify)rcm_clean_notification_subscribers);
		notification_subscribers = NULL;
	}
	if(write_ids)
	{
		g_slist_free_full(write_ids, (GDestroyNotify)rcm_clean_write_ids);
		write_ids = NULL;
	}
    if(addr_mapping_list){
    	g_slist_free_full(addr_mapping_list, (GDestroyNotify)clean_mapping_element);
    	addr_mapping_list = NULL;
    }
}

static void rcm_proxy_exit(void)
{
    TRACE_FUNCTION;
	//HUI: Free memory
	rcm_free_allocated_memory();

    rcm_gdbus_stop_server();

    g_async_queue_unref(output_queue);

    g_socket_service_stop((GSocketService*)service);
    g_socket_listener_close((GSocketListener *)service);
 //   g_free(service);
//	dbus_message_unref(msg);
//	dbus_message_unref(reply);
//	dbus_connection_close(dbus_connection);
//	close(socket_desc);
	//btd_unregister_adapter_driver(&my_driver);
}

BLUETOOTH_PLUGIN_DEFINE(rcm_proxy, VERSION,
		BLUETOOTH_PLUGIN_PRIORITY_LOW, rcm_proxy_init, rcm_proxy_exit)
