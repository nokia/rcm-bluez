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
// Specific headers

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

#include "complete_structures.h"
#include "dbus-server.c"

// For socket management
#include <stdio.h>
//#include <netinet/in.h>
#include <unistd.h>    //write
#include <arpa/inet.h> //inet_addr

//For dbus
//#include "gdbus/gdbus.h"

//#include "eir_func.c"
#include "common.h"

#include <sys/sendfile.h>
#include <fcntl.h>

#include <sys/time.h>
#include <sys/stat.h>

//#include <glib.h>
//#include <gio/gio.h>

#include <gio/gnetworking.h>
//#include <dbus/dbus.h>
//#include <dbus/dbus-glib.h>

#define BLUEZ_BUS_NAME "org.bluez"
#define BLUEZ_INTF_ADAPTER "org.bluez.Adapter1"
#define BLUEZ_INTF_DEVICE "org.bluez.Device1"
#define BLUEZ_INTF_CHAR "org.bluez.GattCharacteristic1"

//HUI
#define NB_ADV_MAX_FILTER_SET 3
#define NB_ADV_MAX_NO_FILTER 1000

///////////////////////////
#define BUFFER_QUERY_SIZE 3000
#define BUFFER_REPLY_SIZE 3000

// --------------------------------------------------------------------------------------------------

static DBusConnection *dbus_connection = NULL;

static bool send_scan_results = true; // XXX Temporary for debugging !!! Should be removed

static bool sending_cache_info = false;

// How many advertisements will be sent to the remote client
// there is no need to send all of them, the limited amount (even 1) is sufficient.
// We use 3 (cf. NB_ADV_MAX) by default to protect against the packet loss
//static int nb_advertisements = 0;

// Tracing
static FILE *trace_file;
static char* path_to_trace;
static struct timeval tv_send, tv_recv, tv_diff;
// End of tracing

struct btd_adapter * default_adapter;
GThreadedSocketService * service = NULL;

typedef struct remote_client {
	char *app_id;
	uint8_t wait_for_reply; // the code of the message the client is waiting for reply to
	int nb_advertisements;
	GSList *uuids;
} RemoteClient;

typedef struct active_connection {
	char * mac_address;
	GSocketConnection * connection; // socket connection corresponding to a given client
	GSList *remote_clients;
	GSList *authorized_devices;
} ActiveConnection;

GSList *c_connections = NULL;				// ActiveConnection

// Quick implementation of the multi-client functionality
// Trash coding part
static bool test = false;
static bool discovery_is_running = false;

typedef struct known_device {
	bdaddr_t bdaddr;
	uint8_t addr_type;
	uint8_t *adv_reply;
	size_t adv_size;
	struct btd_device *device;
	bool device_connected;
} KnownDevice;

GSList *known_device_list = NULL;//HUI

typedef struct pending_response {
	uint8_t *data_to_send;
	size_t data_len;
	guint16 port;
	GSocketConnection * connection;
} PendingResponse;

GAsyncQueue * output_queue;
static bool can_send = true;

//HUI
typedef struct asked_client {
	GSocketConnection * connection;
	bool has_cache_info;
} AskedClient;

typedef struct connected_device_data {
	struct btd_device *device;
	struct btd_adapter * adapter;
	GSList *client_list;//Hui: each element is AskedClient
	uint8_t *connection_reply;//[BUFFER_REPLY_SIZE];//new
	size_t connection_reply_len;//new
	bool remote_connected;//new
} ConnectedDeviceData;

GSList *connected_device_list = NULL;//HUI

// End of multiclient

static bool discovery_started_remotely = false;

// --------------------------------------------------------------------------------------------------

//HUI
static void send_packet( GSocketConnection	*connection,
						 uint8_t			 reply_code,
						 gpointer			 data,
						 gsize				 data_len);

ConnectedDeviceData *get_device_in_connected_device_list( struct btd_device	*device);

ConnectedDeviceData *create_connected_device_data( struct btd_adapter	*adapter,
												   struct btd_device	*device,
												   GSocketConnection 	*connection,
												   bool	 				 cache_updated,
												   bool					 is_remote);

AskedClient *create_asked_client( GSocketConnection	*connection, bool cache_updated);

GSList *get_clients_by_bool_cache( ConnectedDeviceData	*connected_dev_data);

KnownDevice *get_device_in_known_device_list( struct btd_device	*device);

KnownDevice *create_known_device( struct btd_adapter	*adapter,
								  struct btd_device		*device,
								  const bdaddr_t		*bdaddr,
								  uint8_t				 addr_type,
								  uint8_t				*value,
								  uint8_t				 value_len);

ActiveConnection *create_active_connection( GSocketConnection	*connection);

ActiveConnection *get_connection_by_connection_id( GSocketConnection	*connection);

ActiveConnection *get_connection_by_mac_addr( char	*mac_addr);

ActiveConnection *get_connection_by_client( RemoteClient	*remote_client);

RemoteClient *create_remote_client( GSocketConnection	*connection,
									char				*app_id,
									uint8_t				 appid_len);

RemoteClient *get_remote_client_by_app_id( GSocketConnection	*connection,
										   char					*app_id);

GSList *get_client_by_code( uint8_t	reply_code);

static guint16 get_connection_port( GSocketConnection	*connection);

static char *get_connection_addr( GSocketConnection		*connection);

static void remote_cmd_stop_discovery( struct btd_adapter	*adapter);

static void send_bytes_async( GSocketConnection		*connection,
							  gpointer			 	 data,
							  gsize				 	 data_len,
							  GAsyncReadyCallback	 callback // Pass NULL to use the default callback 'callback_send_bytes_async' (see common.c)
							 );

static void print_element( ActiveConnection	*connection,
						   gpointer			 user_data);
//HUI
static void free_allocated_memory(void);

// --------------------------------------------------------------------------------------------------

void get_client_filter(gchar *mac, void *g_v_builder)
{
    TRACE_FUNCTION;

    ActiveConnection *connection = get_connection_by_mac_addr(mac);

    if(!connection || connection->authorized_devices == NULL)
    {
    	g_variant_builder_add ((GVariantBuilder *)g_v_builder, "s", "empty");
    	return;
    }

    g_slist_foreach(connection->authorized_devices, (GFunc)make_filter_gvariant, g_v_builder);
}

void set_client_filter(gchar *mac, ConfigEntry *filter_entry)
{
	TRACE_FUNCTION;

	ActiveConnection *connection = get_connection_by_mac_addr(mac);
	if(!connection)
		return;

	connection->authorized_devices = g_slist_append(connection->authorized_devices, filter_entry);
}

gboolean connection_exists(gchar *mac)
{
	ActiveConnection *connection = get_connection_by_mac_addr(mac);
	if(!connection) return FALSE;
	return TRUE;
}

GSList * check_autorized(gchar *mac, gchar *address)
{
	ActiveConnection *connection = get_connection_by_mac_addr(mac);
	if(!connection) return NULL;

	return g_slist_find_custom(connection->authorized_devices, address, find_filter_element);
}

static void init_pending_response(PendingResponse *response)
{
	response->connection = NULL;
	response->data_len = 0;
}

static void clear_pending_response(PendingResponse *response)
{
	TRACE_FUNCTION;
	if(response->data_to_send) free(response->data_to_send);
	if(response->connection) g_free(response->connection);
//	if(response->data_to_send) g_free(response->data_to_send);
}

static void destroy_response(PendingResponse *response)
{
	TRACE_FUNCTION;
	clear_pending_response(response);
	g_free(response);
}

static void clear_remote_client(RemoteClient *remote_client)
{
	if(!remote_client->uuids)
		g_slist_free_full(remote_client->uuids, g_free);
	g_free(remote_client);
}

static void clear_autorized_devices(ConfigEntry *entry)
{
	g_free(entry->dev_address);
	g_free(entry->dev_name);
	g_free(entry);
}

static void clear_active_connection_data(ActiveConnection *c_connection)
{
	TRACE_FUNCTION;
	g_slist_foreach(c_connection->remote_clients, (GFunc)clear_remote_client, NULL);
	g_slist_foreach(c_connection->authorized_devices, (GFunc)clear_autorized_devices, NULL);

}

static void clear_known_device(KnownDevice *known_dev)
{
	TRACE_FUNCTION;
	free(known_dev->adv_reply);
	free(known_dev);
}

static void clear_asked_client(AskedClient *asked_client)
{
	TRACE_FUNCTION;
//	free(asked_client->connection);
	free(asked_client);
}

static void clear_connected_device_data(ConnectedDeviceData *connected_dev_data)
{
	TRACE_FUNCTION;

	if(connected_dev_data->client_list)
		g_slist_foreach(connected_dev_data->client_list, (GFunc)clear_asked_client, NULL);
	free(connected_dev_data->connection_reply);
	free(connected_dev_data);
}

static void callback_send_bytes_async(	GObject      *source_object,
										GAsyncResult *res,
										gpointer      user_data)
{
    TRACE_FUNCTION;
    GError            * error = NULL;
    GSocketConnection * connection = user_data;
    GOutputStream     * ostream;
    gssize num_bytes_written;

    if(test)
    {
//    	gettimeofday(&tv_recv, NULL);
    	test = false;
    }

    ostream = g_io_stream_get_output_stream(G_IO_STREAM(connection));
    num_bytes_written = g_output_stream_write_bytes_finish(ostream, res, &error);

    can_send = true;

    if (error)
    {
        g_error(error->message);
        return;
    }

    gpointer data = g_async_queue_try_pop(output_queue);
    if(!data) return;

    PendingResponse *pkt = data;

    if (g_socket_connection_is_connected(pkt->connection))
    {
    	send_bytes_async(pkt->connection, pkt->data_to_send, pkt->data_len, NULL);
    	test = true;
    }
    else
    {
    	DBG("Not connected\n");
    }

//    destroy_response(pkt);
    free(pkt->data_to_send);
    g_free(pkt);
}

static void send_bytes_async( GSocketConnection		*connection,
							  gpointer				 data,
							  gsize					 data_len,
							  GAsyncReadyCallback	 callback // Pass NULL to use the default callback 'callback_send_bytes_async' (see common.c)
							 )
{
    TRACE_FUNCTION;
    can_send = false;
    GOutputStream * ostream = g_io_stream_get_output_stream(G_IO_STREAM(connection));
    print_hex(data, data_len);
    g_output_stream_write_async(ostream,
    							data, data_len,
								0,
								NULL,
								callback ? callback : callback_send_bytes_async,
								connection);
}

static void create_trace_file()
{
    TRACE_FUNCTION;
	// Let's create a file to keep tracing
	const char* dir = "./result_traces/";
	const char* file_name = "connection_delay_trace";
	const size_t path_size = strlen(dir) + strlen(file_name) + 1;
	path_to_trace = malloc(path_size);
	if(path_to_trace)
	{
		snprintf(path_to_trace, path_size, "%s%s", dir, file_name);
	}
	else
		DBG("No path_to_trace!!!");
}

static void open_trace_file()
{
    TRACE_FUNCTION;
	trace_file = fopen(path_to_trace, "ab+"); // Open for read, write and create the file if necessary

	if(!trace_file)
	{
		DBG("Failed to open the trace file ! %s", path_to_trace);
		exit(1);
	}
	else
	{
		DBG("Trace file is successfully opened!");
	}
}

static float tv2fl( struct timeval tv)
{
    TRACE_FUNCTION;
	return (float)(tv.tv_sec*1000.0) + (float)(tv.tv_usec/1000.0);
}

int pkt_num = 0;
void write_trace()
{
    TRACE_FUNCTION;
	if(!trace_file)
		open_trace_file();

	timersub(&tv_recv, &tv_send, &tv_diff);
	fprintf(trace_file, "%.6f %.6f %.6f ms %ld.%06ld %ld.%06ld %ld.%06ld mks\n", tv2fl(tv_send), tv2fl(tv_recv), tv2fl(tv_diff),
																					tv_send.tv_sec, tv_send.tv_usec, tv_recv.tv_sec, tv_recv.tv_usec,
																					tv_diff.tv_sec, tv_diff.tv_usec);
// Another way to do it
//	fprintf(trace_file, "temps en us: %ld us\n", ((tv_recv.tv_sec - tv_send.tv_sec) * 1000000 + tv_recv.tv_usec) - tv_send.tv_usec);
}

//HUI
static int cmp_connection_code( gconstpointer a,
								gconstpointer b)
{
	const RemoteClient *remote_client = a;
	const uint8_t code = GPOINTER_TO_UINT(b);

	return remote_client->wait_for_reply == code ? 0 : -1;
}

GSList *get_client_by_code( uint8_t reply_code)
{
	TRACE_FUNCTION;
	GSList *list, *l;
	GSList *discovery_list = NULL;

	DBG("Looking for connection waiting the reply for code = %s\n", code_to_str(reply_code));

	for(list = c_connections; list != NULL; list = list->next)
	{
		ActiveConnection *conn = list->data;
		l = g_slist_find_custom(conn->remote_clients, GUINT_TO_POINTER(reply_code), cmp_connection_code);
		if(l)
			discovery_list = g_slist_append(discovery_list, l->data);
		continue;
	}

	if (!discovery_list)
	{
		DBG("Corresponding connection wasn't found!\n");
		return NULL;
	}
	return discovery_list;
}

//HUI
KnownDevice *create_known_device( struct btd_adapter	*adapter,
								  struct btd_device 	*device,
								  const bdaddr_t 		*bdaddr,
								  uint8_t				 addr_type,
								  uint8_t				*value,
								  uint8_t				 value_len)
{
	TRACE_FUNCTION;
	KnownDevice *known_dev = malloc(sizeof(KnownDevice));
	known_dev->device = device;
	known_dev->addr_type = addr_type;
	known_dev->bdaddr = *bdaddr;
	known_dev->adv_reply = malloc(value_len);
	memcpy(known_dev->adv_reply, value, value_len);
	known_dev->adv_size = value_len;

	known_device_list = g_slist_append(known_device_list, known_dev);
	DBG("RCM: device = %p added to known_device_list\n", device);

	return known_dev;
}

static int cmp_remote_client( gconstpointer a,
							  gconstpointer b)
{
	TRACE_FUNCTION;
	return a == b ? 0 : -1;
}

ActiveConnection *get_connection_by_client( RemoteClient *remote_client)
{
	TRACE_FUNCTION;
	GSList *list, *l;
	ActiveConnection *conn;

	for(list = c_connections; list != NULL; list = list->next)
		{
			conn = list->data;
			l = g_slist_find_custom(conn->remote_clients, remote_client, cmp_remote_client);
			if(l)
				return conn;
		}

	DBG("Corresponding connection wasn't found!\n");
	return NULL;

}

static gint g_strcmp( gconstpointer a,
					  gconstpointer b)
{
	TRACE_FUNCTION;
	return strcmp(a, b);
}

//HUI
static bool is_remote_filter_match( GSList	*discovery_filter,
									GSList	*dev_uuids)
{
	TRACE_FUNCTION;
	GSList *m;
	bool got_match = false;

	if (!discovery_filter)
		got_match = true;
	else {
		for (m = discovery_filter; m != NULL && got_match != true;
						m = m->next) {
			if (g_slist_find_custom(dev_uuids,
						m->data,
						g_strcmp) != NULL)
			{
				got_match = true;
			}
		}
	}
	return got_match;
}

static void device_found( uint16_t		index,
		   	   	   	   	  uint16_t		length,
						  const void   *param,
						  void		   *user_data)
{
    TRACE_FUNCTION;
	if(send_scan_results)
	{
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
		DBG("DEVICE NAME IS UTF8 = %d\n", ok);
		if(ok && eir_data.name != NULL)
			device_name = g_strdup(eir_data.name);
		else
			device_name = g_strdup(empty_name);

/*
		if(strcmp(&(eir_data.name), "") == 0 || strcmp(&(eir_data.name), " ") == 0)
			device_name = g_strdup(empty_name);
		else
			device_name = g_strdup(eir_data.name);
*/
		if(initialization_phase)
		{
			// We are building the init filter here
			GVariant *g = g_variant_new ("(ssqb)", device_name, addr, ev->addr.type, 0);
			send_rcm_gdbus_signal("DeviceFound", g);
			return;
		}
		else
		{
			GSList * found_el = g_slist_find_custom(init_filter, &addr, find_filter_element);
			if (found_el == NULL) return; // Don't continue if the device is not in the init filter list
		}

		// Crafting the reply (header + data)
		size_t eir_size = eir_len;
		size_t data_size = 0;
		uint8_t *buffer_reply = malloc(REPLY_HEADER_SIZE + 1 + 1 + strlen(addr) + 1 + eir_size);//[BUFFER_REPLY_SIZE];

		buffer_reply[data_size] = REMOTE_CMD_START_DISCOVERY; // HEADER
		data_size += REPLY_HEADER_SIZE;

		buffer_reply[data_size] = ev->addr.type;
		data_size += 1;

		buffer_reply[data_size] = strlen(addr);
		data_size += 1;

		memcpy(&buffer_reply[data_size], addr, strlen(addr));
		data_size += strlen(addr);

		//HUI
		buffer_reply[data_size] = eir_size;
		data_size += 1;

		memcpy(&buffer_reply[data_size], eir, eir_size);
		data_size += eir_size;

//HUI: For test**************************************************************
//		DBG("dev_address = %s, eir_size = %d, eir_name = %s\n", addr, eir_size, eir_data.name);
//		DBG("eir_data.name pointer %p\n", eir_data.name);
//*****************************************************************************

		GSList *discovery_list = get_client_by_code(REMOTE_CMD_START_DISCOVERY);
//		DBG("RCM: Print discovery_list!!\n");
//		g_slist_foreach(discovery_list, (GFunc)print_element, NULL);

		if(!discovery_list)
		{
			DBG("RCM: No client requests scanning, STOP DISCOVERY!\n");
			remote_cmd_stop_discovery(default_adapter);
		}
		else
		{
			GSList *l;
			for(l = discovery_list; l != NULL; l = l->next)
			{
				RemoteClient *remote_client = l->data;
				ActiveConnection *conn = get_connection_by_client(remote_client);
				GSList * found_el = g_slist_find_custom(conn->authorized_devices, &addr, find_filter_element);

				gboolean passed = FALSE;

				//HUI: if filter is set, send 3 times to client
				if(remote_client->uuids &&
						is_remote_filter_match(remote_client->uuids, eir_data.services) &&
						remote_client->nb_advertisements < NB_ADV_MAX_FILTER_SET &&
						found_el)
				{
					passed = TRUE;
					DBG("RCM: device passed filter!\n");
					send_packet(conn->connection, REMOTE_CMD_START_DISCOVERY, buffer_reply, data_size);
					remote_client->nb_advertisements++;
					GVariant *g = g_variant_new ("(ssqb)", device_name, addr, ev->addr.type, passed);
					send_rcm_gdbus_signal("DeviceFound", g);
				}

				//HUI: if no filter set, send pkt to client
				else if(!remote_client->uuids &&
						remote_client->nb_advertisements < NB_ADV_MAX_NO_FILTER &&
						found_el)
				{
					send_packet(conn->connection, REMOTE_CMD_START_DISCOVERY, buffer_reply, data_size);
					remote_client->nb_advertisements++;
					GVariant *g = g_variant_new ("(ssqb)", device_name, addr, ev->addr.type, passed);
					send_rcm_gdbus_signal("DeviceFound", g);
				}
			}

			g_free(device_name);
			//if device is not in the known_device_list, store device info
			struct btd_device *device = btd_adapter_find_device(adapter, &ev->addr.bdaddr, ev->addr.type);
			KnownDevice *known_dev = get_device_in_known_device_list(device);
			if(!known_dev)
				known_dev = create_known_device(adapter, device, &ev->addr.bdaddr, ev->addr.type, buffer_reply, data_size);
			else
				DBG("RCM: Device is already in known_device_list\n");
		}
		free(buffer_reply);
	}
}

static void gdbus_config()
{
    TRACE_FUNCTION;
	DBusError* error = NULL;

	dbus_connection = dbus_bus_get(DBUS_BUS_SYSTEM, error);

	if(error)
	{
		DBG("Unable to get dbus connection %s\n", error->message);
	}
	DBG("Got DBus connection %p\n", dbus_connection);

}

static guint16 get_connection_port( GSocketConnection *connection)
{
	TRACE_FUNCTION;
	GSocketAddress *sockaddr = g_socket_connection_get_remote_address(connection, NULL);
	guint16 port = g_inet_socket_address_get_port(G_INET_SOCKET_ADDRESS(sockaddr));

	return port;
}

//HUI
static char * get_connection_addr( GSocketConnection *connection)
{
	TRACE_FUNCTION;
	GSocketAddress *sockaddr = g_socket_connection_get_remote_address(connection, NULL);
	GInetAddress *addr = g_inet_socket_address_get_address(G_INET_SOCKET_ADDRESS(sockaddr));
	char* conn_addr = g_inet_address_to_string(addr);
	return conn_addr;
}

//HUI
static int cmp_connection_id( gconstpointer a,
							  gconstpointer b)
{
	TRACE_FUNCTION;
	const ActiveConnection *conn = a;
	const GSocketConnection *connection = b;

	return conn->connection == connection ? 0 : -1;
}

ActiveConnection *get_connection_by_connection_id( GSocketConnection *connection)
{
	TRACE_FUNCTION;
	GSList *list;
	ActiveConnection *c_connection;

	DBG("Looking for connection = %p\n", connection);
	list = g_slist_find_custom(c_connections, connection,
								cmp_connection_id);
	if (!list)
	{
		DBG("Corresponding connection wasn't found!\n");
		return NULL;
	}

	c_connection = list->data;

	return c_connection;
}

static int cmp_mac_address( gconstpointer a,
							gconstpointer b)
{
	TRACE_FUNCTION;
	const ActiveConnection *conn = a;
	const char *mac_addr = b;

	if(conn->mac_address == NULL)
		return -1;
	else
		return g_strcmp(conn->mac_address, mac_addr);
}

ActiveConnection *get_connection_by_mac_addr( char	*mac_addr)
{
	TRACE_FUNCTION;
	GSList *list;
	ActiveConnection *c_connection;

	DBG("Looking for mac address in active connection = %s\n", mac_addr);
	list = g_slist_find_custom(c_connections, mac_addr, cmp_mac_address);
	if (!list)
	{
		DBG("Corresponding mac address wasn't found!\n");
		return NULL;
	}

	c_connection = list->data;

	return c_connection;
}

//HUI
static void remote_cmd_set_discovery_filter( GSocketConnection	*connection,
											 char				*app_id,
											 struct btd_adapter	*adapter,
											 GSList				*uuid_list)
{
	TRACE_FUNCTION;
	RemoteClient *remote_client = get_remote_client_by_app_id(connection, app_id);
	remote_client->uuids = uuid_list;

	// We finally never send this message to do not penalize other clients
	// Filtering is done in the rcm_proxy itself in the device_found function
/*
	//craft dbus msg include uuid..
	DBG("Calling SetDiscoveryFilter through DBus, adapter id = %d\n", adapter->dev_id);

	DBusMessage *msg = NULL;
	msg = dbus_message_new_method_call(BLUEZ_BUS_NAME,
									   adapter->path,
									   BLUEZ_INTF_ADAPTER,
									   "SetDiscoveryFilter");

	//Append param to the message
	DBusMessageIter discovfil_iter, discovfil_dict;
	dbus_message_iter_init_append(msg, &discovfil_iter);
	dbus_message_iter_open_container(&discovfil_iter, DBUS_TYPE_ARRAY,
									 DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
									 DBUS_TYPE_STRING_AS_STRING
									 DBUS_TYPE_VARIANT_AS_STRING
									 DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &discovfil_dict);
	if(uuid_list != NULL)
	{
		DBusMessageIter entry, value, arrayIter;
		char *uuids = "UUIDs";
		GSList *list;

		dbus_message_iter_open_container(&discovfil_dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &uuids);
		dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "as", &value);
		dbus_message_iter_open_container(&value, DBUS_TYPE_ARRAY, "s", &arrayIter);

		for (list = g_slist_nth(uuid_list, 0); list; list = g_slist_next(list))
		{
			dbus_message_iter_append_basic(&arrayIter, DBUS_TYPE_STRING, &list->data);
		}

		dbus_message_iter_close_container(&value, &arrayIter);
		dbus_message_iter_close_container(&entry, &value);
		dbus_message_iter_close_container(&discovfil_dict, &entry);
	}

	dbus_message_iter_close_container(&discovfil_iter, &discovfil_dict);
	DBG("DBus message pointer = %p", msg);

	gboolean ok = g_dbus_send_message(dbus_connection, msg);
	DBG("DBus message sent %d", ok);
*/

}

//HUI
static int cmp_known_device( gconstpointer a,
							 gconstpointer b)
{
	TRACE_FUNCTION;
	const KnownDevice *known_dev = a;
	const struct btd_device *device = b;
	return known_dev->device == device ? 0 : -1;
}

KnownDevice *get_device_in_known_device_list( struct btd_device *device)
{
	TRACE_FUNCTION;
	GSList *list;
	KnownDevice *known_dev;
	list = g_slist_find_custom(known_device_list, device, cmp_known_device);
	if (!list)
	{
		DBG("RCM: Corresponding device wasn't found!\n");
		return NULL;
	}
	known_dev = list->data;
	return known_dev;
}

ConnectedDeviceData *find_connected_dev_by_filter( GSList *uuids)
{
	TRACE_FUNCTION;
	GSList *l;
	for(l = connected_device_list; l != NULL; l = l->next)
	{
		ConnectedDeviceData *connected_dev_data = l->data;

		if(is_remote_filter_match(uuids, connected_dev_data->device->uuids))
		{
			return connected_dev_data;
		}
	}
	DBG("RCM: no matching device!!\n");
	return NULL;
}

static void send_connected_device_info( ConnectedDeviceData	*connected_dev_data,
								 	    GSocketConnection	*connection)
{
	TRACE_FUNCTION;

	gboolean in_use;

	KnownDevice *known_dev = get_device_in_known_device_list(connected_dev_data->device);

	if(!connected_dev_data->remote_connected)
		in_use = true;
	else
		in_use = false;

	size_t data_size = 0;
	uint8_t *buffer_reply = malloc(known_dev->adv_size + 1);//[BUFFER_REPLY_SIZE];

	memcpy(&buffer_reply[data_size], known_dev->adv_reply, known_dev->adv_size);
	data_size += known_dev->adv_size;

	buffer_reply[data_size] = in_use;
	data_size += 1;

	send_packet(connection, REMOTE_CMD_START_DISCOVERY, buffer_reply, data_size);
	free(buffer_reply);
}

static void trigger_new_discovery( struct btd_adapter	*adapter)
{
	TRACE_FUNCTION;
	DBG("Calling StartDiscovery through DBus, adapter id = %d\n", adapter->dev_id);
	send_scan_results = true;

	DBusMessage *msg = NULL;
	DBusMessage *reply;

	msg = dbus_message_new_method_call(BLUEZ_BUS_NAME,
			adapter->path,
			BLUEZ_INTF_ADAPTER,
			"StartDiscovery");
//	DBG("DBus message pointer = %p", msg);
	gboolean ok = g_dbus_send_message(dbus_connection, msg);
//	DBG("DBus message sent %d", ok);

	discovery_started_remotely = true;
	discovery_is_running = true;

//	dbus_message_unref(msg);//what is this???
}

//HUI
static void remote_cmd_start_discovery( GSocketConnection	*connection,
										char				*app_id,
										struct btd_adapter	*adapter)
{
	TRACE_FUNCTION;
	guint16 port = get_connection_port(connection);
	char* conn_addr = get_connection_addr(connection);
	DBG("RCM: get connection address = %s, port = %d, connection pointer is %p\n", conn_addr, port, connection);

	RemoteClient *remote_client = get_remote_client_by_app_id(connection, app_id);

	if(!discovery_is_running)
	{
		//
//		ActiveConnection *conn = get_connection_by_client(remote_client);
//		GSList * found_el = g_slist_find_custom(conn->authorized_devices, &addr, find_filter_element);

		// TODO: this must be revised! We send only one (!!!) device between connected ones.
		// Moreover, if a client does not configure filters, it will get no info about the connected devices.
		if(remote_client->uuids)//filter is set TODO: ADD CLIENT FILTER CHECK HERE
		{
			ConnectedDeviceData *connected_dev_data= find_connected_dev_by_filter(remote_client->uuids);

			//if desired device is already connected
			if(connected_dev_data)
			{
				DBG("RCM: Desired device is already connected, reply to client immediately\n");
				send_connected_device_info(connected_dev_data, connection);
			}
//			always trigger new discovery, different devices may have the same uuid
			trigger_new_discovery(adapter);

		}
		else
		{
			//no filter, reply from connected device list, then trigger new discovery
			g_slist_foreach(connected_device_list, (GFunc)send_connected_device_info, connection);
			trigger_new_discovery(adapter);
		}
	}
	else if(discovery_is_running)
	{
		DBG("RCM: Discovery is running! Get reply from device_found()\n");
	}
}

static void remote_cmd_stop_discovery( struct btd_adapter	*adapter)
{
    TRACE_FUNCTION;
// TODO Check whether discovery has been started by an authorized client. If not, ignore.
	if(discovery_is_running || initialization_phase)
	{
		send_scan_results = false;
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

static void cmd_stop_discovery( void	*user_data)
{
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

static void stop_init_start_discovery( void	*user_data)
{
	DBG("-----------------------------------------------------------------------");
	DBG("Stop INIT Discovery! initialization_phase = %d\n", initialization_phase);
	remote_cmd_stop_discovery(default_adapter);
}

//HUI
static int cmp_connected_device( gconstpointer a,
								 gconstpointer b)
{
    TRACE_FUNCTION;
	const ConnectedDeviceData *connected_dev_data = a;
	const struct btd_device *device = b;
	return connected_dev_data->device == device ? 0 : -1;
}

ConnectedDeviceData *get_device_in_connected_device_list( struct btd_device	*device)
{
    TRACE_FUNCTION;
	GSList *list;
	ConnectedDeviceData *connected_dev_data;
	list = g_slist_find_custom(connected_device_list, device, cmp_connected_device);
	if (!list)
	{
		DBG("RCM: Corresponding device wasn't found!\n");
		return NULL;
	}
	connected_dev_data = list->data;
	return connected_dev_data;
}

GSList *get_clients_by_bool_cache( ConnectedDeviceData	*connected_dev_data)
{
    TRACE_FUNCTION;
	GSList *list;
	GSList *no_cache_list = NULL;

	DBG("RCM: Looking for client with has_cache_info = false\n");
	for(list = connected_dev_data->client_list; list != NULL; list = list->next)
	{
		AskedClient *asked_client = list->data;
		if(asked_client->has_cache_info == false)
			no_cache_list = g_slist_append(no_cache_list, asked_client);
	}

	if (!no_cache_list)
	{
		DBG("RCM: Corresponding client wasn't found!\n");
		return NULL;
	}
//	asked_client = list->data;

	return no_cache_list;
}

static void send_cache_info( void	*userdata)
{
    TRACE_FUNCTION;
	sending_cache_info = true;
	struct btd_device *device = userdata;
	GSList *no_cache_list;

	//HUI: check if any client needs cache file
	ConnectedDeviceData *connected_dev_data = get_device_in_connected_device_list(device);
	if(connected_dev_data)
	{
		no_cache_list = get_clients_by_bool_cache(connected_dev_data);
		if(!no_cache_list)
			return;
	}

	struct btd_adapter *adapter = device->adapter;
	char filename[PATH_MAX], local[18], peer[18];
	int fd;
	struct stat file_stat;
	char file_size[256];
	ssize_t len;

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

		fprintf(stdout, "File Size: \n%d bytes\n", file_stat.st_size);
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
			ssize_t data_size = 0;

			buffer_reply[data_size] = REMOTE_CMD_CACHE_INFO; // HEADER
			data_size += REPLY_HEADER_SIZE;

			// Size of the file
			memcpy(&buffer_reply[data_size], &lSize, sizeof(lSize));
			data_size += sizeof(lSize);

			strncpy(&buffer_reply[data_size], file_buffer, lSize+1);

			data_size += lSize;

			GSList *l;
			for(l = no_cache_list; l != NULL; l = l->next)
			{
				AskedClient *asked_client = l->data;
				send_packet(asked_client->connection, REMOTE_CMD_CACHE_INFO, buffer_reply, data_size);
				asked_client->has_cache_info = true;
			}
			free(buffer_reply);
		}
		fclose(fp);
		free(file_buffer);
}

static void connection_result( uint16_t		 index,
							   uint16_t		 length,
							   const void	*param,
							   void			*user_data)
{
    TRACE_FUNCTION;
	// Write the time where the connection is successfully established
	gettimeofday(&tv_recv, NULL);
	write_trace();

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


	buffer_reply[data_size] = REMOTE_CMD_CONNECT_DEVICE; // HEADER
	data_size += REPLY_HEADER_SIZE;

	buffer_reply[data_size] = ev->addr.type;
	data_size += 1;

	buffer_reply[data_size] = strlen(ev_device_addr);
	data_size += 1;

	memcpy(&buffer_reply[data_size], ev_device_addr, strlen(ev_device_addr));
	data_size += strlen(ev_device_addr);

	memcpy(&buffer_reply[data_size], eir, eir_size);
	data_size += eir_size;

	//HUI: only 1st client who connects with this device will call this function
	ConnectedDeviceData *connected_dev_data = get_device_in_connected_device_list(ev_device);
	if(connected_dev_data != NULL)
	{
		connected_dev_data->connection_reply = malloc(data_size);
		memcpy(connected_dev_data->connection_reply, buffer_reply, data_size);
		connected_dev_data->connection_reply_len = data_size;
		g_printf("---------------------------- Inside connection result, buffer_reply: \n");
		display_reply_hex(data_size, buffer_reply);
		g_printf("connection_reply (should be a copy of buffer_reply): \n");
		display_reply_hex(connected_dev_data->connection_reply_len, connected_dev_data->connection_reply);
		g_printf("----------------------------\n");

		AskedClient *client = g_slist_nth_data(connected_dev_data->client_list, 0);
		send_packet(client->connection, REMOTE_CMD_CONNECT_DEVICE, buffer_reply, data_size);

		// Send gdbus signal
		GVariant *signal_data;
		signal_data = g_variant_new ("(s)", g_strdup_printf ("%s", ev_device_addr));
		send_rcm_gdbus_signal("DeviceConnected", signal_data);
	}

	KnownDevice *known_dev = get_device_in_known_device_list(ev_device);
	if(known_dev != NULL)
	{
		known_dev->device_connected = true;
	}
	free(buffer_reply);
}

static int cmp_asked_client( gconstpointer a,
							 gconstpointer b)
{
    TRACE_FUNCTION;
	const AskedClient *asked_client = a;
	const GSocketConnection * connection = b;

	return asked_client->connection == connection ? 0 : -1;
}

AskedClient *create_asked_client( GSocketConnection	*connection,
								  bool				 cache_updated)
{
    TRACE_FUNCTION;
	AskedClient *asked_client = malloc(sizeof(AskedClient));
	asked_client->connection = connection;
	asked_client->has_cache_info = cache_updated;

	return asked_client;
}

//HUI
ConnectedDeviceData *create_connected_device_data( struct btd_adapter	*adapter,
												   struct btd_device	*device,
												   GSocketConnection	*connection,
												   bool					 cache_updated,
												   bool					 is_remote)
{
    TRACE_FUNCTION;
	ConnectedDeviceData *connected_dev_data = get_device_in_connected_device_list(device);
	if(connected_dev_data == NULL)
	{
		DBG("RCM: create new connected_device_data!\n");
		ConnectedDeviceData *connected_dev_data = malloc(sizeof(ConnectedDeviceData));
		connected_dev_data->adapter = adapter;
		connected_dev_data->device = device;
		connected_dev_data->remote_connected = is_remote;
		connected_dev_data->client_list = NULL;

		AskedClient *asked_client = create_asked_client(connection, cache_updated);
		connected_dev_data->client_list = g_slist_append(connected_dev_data->client_list, asked_client);

		connected_device_list = g_slist_append(connected_device_list, connected_dev_data);
	}
	return connected_dev_data;
}

static void device_connect( GSocketConnection	*connection,
							struct btd_adapter	*adapter,
							const bdaddr_t		 bdaddr,
							uint8_t				 addr_type,
							bool				 cache_updated)
{
    TRACE_FUNCTION;

	struct btd_device *device = btd_adapter_find_device(adapter, &bdaddr, addr_type);
	if(device == NULL)
	{
		DBG("No Device found!!!\n");
		return;
	}

	KnownDevice *known_dev = get_device_in_known_device_list(device);

	if(!known_dev->device_connected)
	{
		char address_str[18];
		ba2str(&bdaddr, address_str);

		DBG("Calling \"Connect\" through DBus, adapter id = %d, device_path = %s\n",
				adapter->dev_id,
				device->path);

		ConnectedDeviceData *connected_dev_data = create_connected_device_data(adapter, device, connection, cache_updated, true);

		adapter_connect_ev_cb_register(connection_result);

		// Start connection procedure
		DBusMessage *msg_connect = NULL;
		DBusMessage *reply;

		msg_connect = dbus_message_new_method_call(BLUEZ_BUS_NAME,
												   device->path,
												   BLUEZ_INTF_DEVICE,
												   "Connect");

		gboolean ok_connect = g_dbus_send_message(dbus_connection, msg_connect);
	}
	else if(known_dev->device_connected)
	{
		// add connection in connected_dev_data->client_list
		ConnectedDeviceData *connected_dev_data = get_device_in_connected_device_list(device);
		if(connected_dev_data != NULL)
		{
			GSList *list = g_slist_find_custom(connected_dev_data->client_list, connection, cmp_asked_client);
			if(!list)
			{
				DBG("RCM: add new client in connected_device_data\n");
				AskedClient *asked_client = create_asked_client(connection, cache_updated);
				connected_dev_data->client_list = g_slist_append(connected_dev_data->client_list, asked_client);
			}

			display_reply_hex(connected_dev_data->connection_reply_len, connected_dev_data->connection_reply);
			send_packet(connection, REMOTE_CMD_CONNECT_DEVICE, connected_dev_data->connection_reply, connected_dev_data->connection_reply_len);
			gettimeofday(&tv_recv, NULL);
			write_trace();

			if(cache_updated == false)
				send_cache_info(connected_dev_data->device);
		}
	}
}

//HUI
//ConnectedDeviceData *get_connected_device_by_client(GSocketConnection * connection)
//{
//    TRACE_FUNCTION;
//	GSList *l, *m;
//	for(l = connected_device_list; l != NULL; l = g_slist_next(l))
//	{
//		ConnectedDeviceData *connected_dev_data = l->data;
//		m = g_slist_find_custom(connected_dev_data->client_list, connection, cmp_asked_client);
//		if (m)
//			return connected_dev_data;
//	}
//	return NULL;
//}
static void write_characteristic( GSocketConnection		*connection,
								  char					*char_path,
								  uint8_t			 	 value_len,
								  const uint8_t			*value,
								  struct btd_adapter 	*adapter)
{
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

	msg = dbus_message_new_method_call(BLUEZ_BUS_NAME,
									   complete_path,
									   ///org/bluez/hci0/dev_F8_1D_78_60_3D_D9/service0009/char000a
									   BLUEZ_INTF_CHAR,
									   "WriteValue");

	// Append an argument to the message
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
	gboolean ok = g_dbus_send_message(dbus_connection, msg);
//	dbus_message_unref(msg);
}

static void send_packet( GSocketConnection	*connection,
						 uint8_t			 reply_code,
						 gpointer			 data,
						 gsize				 data_len)
{
	TRACE_FUNCTION;

	//HUI
	DBG("RCM: Send packet to %s: %d, connection pointer is %p, code = %s\n",
			get_connection_addr(connection),
			get_connection_port(connection),
			connection,
			code_to_str(reply_code));

	uint8_t *message = malloc(data_len + 1);
	size_t length = 0;

	message[length] = data_len;
	length += 1;

	memcpy(&message[length], data, data_len);
	length += data_len;

	if(!can_send) // channel is busy, enqueue it for later
	{
		DBG("Can't send, the socket is busy, push it in the queue\n");
		PendingResponse *pkt = malloc(sizeof(PendingResponse));
		init_pending_response(pkt);
		pkt->connection = connection;
		pkt->data_len = length;
		guint16 p = get_connection_port(connection);
		pkt->port = p;
		pkt->data_to_send = malloc(length);
		memcpy(pkt->data_to_send, message, length);

		g_async_queue_push(output_queue, pkt);
		return;
	}
	else
	{
		if (g_socket_connection_is_connected(connection))
		{
			can_send = false; // XXX may be dangerous, added for testing
			send_bytes_async(connection, message, length, NULL);

			guint16 port = get_connection_port(connection);
			GSocketAddress *socket_addr = g_socket_connection_get_remote_address(connection, NULL);
			GInetAddress *src_addr = g_inet_socket_address_get_address(G_INET_SOCKET_ADDRESS(socket_addr));
			guint16 src_port = g_inet_socket_address_get_port(G_INET_SOCKET_ADDRESS(socket_addr));
			gchar *src_addr_str = g_inet_address_to_string(src_addr);

			GVariant *signal_data;
			gchar *string1 = g_strdup_printf ("%s", code_to_str(reply_code));
			gchar *string2 = g_strdup_printf ("%s:%d", src_addr_str, src_port);
			signal_data = g_variant_new ("(ss)", string1, string2);
			send_rcm_gdbus_signal("SendReply", signal_data);

			g_free(src_addr_str);
			g_free(string1);
			g_free(string2);
		}
		else
		{
			DBG("Not connected!\n");
		}
	}
	free(message);
	return;
}

RemoteClient *create_remote_client( GSocketConnection	*connection,
									char				*app_id,
									uint8_t				 appid_len)
{
    TRACE_FUNCTION;
    ActiveConnection *active_connection;
    active_connection = get_connection_by_connection_id(connection);
    RemoteClient *remote_client = malloc(sizeof(RemoteClient));

    char *app_str = malloc(appid_len);
    app_str = app_id;

    remote_client->app_id = app_str;
    remote_client->nb_advertisements = 0;
    remote_client->wait_for_reply = 0;
    remote_client->uuids = NULL;

    active_connection->remote_clients = g_slist_append(active_connection->remote_clients, remote_client);

	return remote_client;
}

static int cmp_app_id( gconstpointer a,
					   gconstpointer b)
{
	TRACE_FUNCTION;
	const RemoteClient *remote_client = a;
	const char *app_id = b;

	DBG("RCM: remote_client->app_id = %s, new appid = %s\n", remote_client->app_id, app_id);

	if(!strcmp(remote_client->app_id, app_id))
		return 0;;

	return -1;
//	return g_strcmp(remote_client->app_id, app_id);
}

static void print_appid( RemoteClient	*remote_client,
						 gpointer		 user_data)
{
    TRACE_FUNCTION;
	DBG("remote_client->app_id = %s\n",
			remote_client->app_id);
}

RemoteClient *get_remote_client_by_app_id( GSocketConnection	*connection,
										   char					*app_id)
{
	TRACE_FUNCTION;
	GSList *list;
	ActiveConnection *active_connection;
	RemoteClient *remote_client;

	active_connection = get_connection_by_connection_id(connection);
	DBG("active_connection %p\n", active_connection);
	g_slist_foreach(active_connection->remote_clients, (GFunc)print_appid, NULL);

	list = g_slist_find_custom(active_connection->remote_clients, app_id, cmp_app_id);
	if (!list)
	{
		DBG("RCM: Corresponding client wasn't found!\n");
		return NULL;
	}
	remote_client = list->data;
	return remote_client;
}

static void set_new_wait_code( GSocketConnection	*connection,
							   char					*app_id,
							   uint8_t				 new_code)
{
    TRACE_FUNCTION;
	RemoteClient *remote_client;

	DBG("for connection = %p, app_id = %s\n", connection, app_id);
	remote_client = get_remote_client_by_app_id(connection, app_id);

//	DBG("old code = %s\n", code_to_str(remote_client->wait_for_reply));
	remote_client->wait_for_reply = new_code;
//	DBG("new code = %s\n", code_to_str(remote_client->wait_for_reply));
}

//HUI
static GSList * remove_from_active_connections( GSocketConnection	*connection)
{
    TRACE_FUNCTION;
	ActiveConnection *conn;
	conn = get_connection_by_connection_id(connection);
	if(conn)
	{
		clear_active_connection_data(conn);
		c_connections = g_slist_remove(c_connections, conn);
		free(conn);
		DBG("RCM: %d active connection(s) left\n", g_slist_length(c_connections));
		return c_connections;
	}
	return NULL;
}

static void cmd_dev_disconnect( struct btd_device	*device)
{
    TRACE_FUNCTION;
	KnownDevice *known_dev = get_device_in_known_device_list(device);
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
		send_rcm_gdbus_signal("DeviceDisconnected", signal_data);
	}
	else
	{
		DBG("Got Disconnect request but the device is not connected\n");
	}
//	dbus_message_unref(msg);
}

static void remove_client_from_connected_device( ConnectedDeviceData	*connected_dev_data,
												 GSocketConnection		*connection)
{
    TRACE_FUNCTION;
	AskedClient *asked_client;
	if(connected_dev_data->client_list != NULL)
	{
		GSList *list = g_slist_find_custom(connected_dev_data->client_list, connection, cmp_asked_client);
		if(list)
		{
			asked_client = list->data;
			connected_dev_data->client_list = g_slist_remove(connected_dev_data->client_list, asked_client);
			free(asked_client);

			//if client_list is empty after remove, disconnect device from proxy, remove from connected_dev_list, free connected_device_data
			if(!g_slist_length(connected_dev_data->client_list))
			{
//				DBG("RCM: NO client connecting with device %p, disconnect with proxy, remove from connected_device_list, free memory!\n", connected_dev_data->device);
				cmd_dev_disconnect(connected_dev_data->device);
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

void process_mac_address( char *mac,
						  char *mac_str,
						  GSocketConnection * connection)
{
    TRACE_FUNCTION;

	tohex(mac, 6, mac_str, 18);
	DBG("mac_str = %s\n", mac_str);

	ActiveConnection *c_connection = get_connection_by_mac_addr(mac_str);
	if(!c_connection)
	{
		//    			memset(mac_addr, 0, 18);
		//    			strncpy(mac_addr, mac_str, 18);

		ActiveConnection *conn = get_connection_by_connection_id(connection);
		// Add here some cheking to manage authorized mac addresses only
		conn->mac_address = g_strdup(mac_str);
		DBG("c_connection->mac_address %s, c_connection %p\n", conn->mac_address, conn);
		//        	g_free(mac_addr);
	}
	else
	{
		if(c_connection->connection != connection)
			c_connection->connection = connection;
	}
}

char * process_appid( uint8_t appid_len,
					  const uint8_t *appid_raw,
					  GSocketConnection * connection)
{
    TRACE_FUNCTION;

	char *app_id;
	app_id = uint8_to_utf8(appid_raw, appid_len, appid_len);
	DBG("RCM: app_id = %s\n", app_id);

	RemoteClient *remote_client = get_remote_client_by_app_id(connection, app_id);
	if(!remote_client)
		remote_client = create_remote_client(connection, app_id, appid_len);
	return app_id;
}

static gboolean callback_read( GIOChannel    *channel,
							   GIOCondition   condition,
							   gpointer       user_data)
{
    TRACE_FUNCTION;
    gssize buffer_len;
//    GIOStatus ret;
    GInputStream* instream = NULL;
    GSocketConnection * connection = G_SOCKET_CONNECTION(user_data);
    GError            * error = NULL;

    guint16 port = get_connection_port(connection);
    GSocketAddress *socket_addr = g_socket_connection_get_remote_address(connection, NULL);
    GInetAddress *src_addr = g_inet_socket_address_get_address(G_INET_SOCKET_ADDRESS(socket_addr));
    guint16 src_port = g_inet_socket_address_get_port(G_INET_SOCKET_ADDRESS(socket_addr));
    GVariant *g = NULL;

    if (condition & G_IO_HUP)
    {
        DBG("The client has disconnected!\n");
        return FALSE; // The client has disconnected abruptly, remove this GSource
    }

    gchar buffer[BUFSIZ]; // Larger than sizeof(reply_t)
    GInputStream * istream = g_io_stream_get_input_stream(G_IO_STREAM(connection));
    buffer_len = g_input_stream_read(istream, buffer, BUFSIZ, NULL, &error);

    switch (buffer_len)
    {
    case -1:
    {
    	g_error("Error reading: %s\n", error->message);
    	g_object_unref(connection);
    	return FALSE;
    }
    case 0:
    {
    	g_print("Client disconnected\n");
    	c_connections = remove_from_active_connections(connection);
    	if(connected_device_list)
    		g_slist_foreach(connected_device_list, (GFunc)remove_client_from_connected_device, connection);

    	GVariant *signal_data;
    	gchar *src_addr_str = g_inet_address_to_string(src_addr);
    	signal_data = g_variant_new ("(sq)", src_addr_str, port);
    	send_rcm_gdbus_signal("ClientDisconnected", signal_data);
    	g_free(src_addr_str);
    	return FALSE; // The client has closed the connection gracefully, remove this GSource
    }
    default:
    	break;
    }

    if (buffer_len)
    {
      	DBG("Received %u bytes\n", buffer_len);
    	display_reply_hex(buffer_len, buffer);

    	gchar *src_addr_str = g_inet_address_to_string(src_addr);
		gchar *addr_port_str = g_strdup_printf ("%s:%d", src_addr_str, src_port);

    	ssize_t curr_length = 0;
    	while(curr_length < buffer_len - 1)
    	{
    		ssize_t byte_iterator = curr_length;

    		// Current packet length
    		ssize_t pkt_len = buffer[byte_iterator];
    		byte_iterator += 1;

    		// Extract and process client MAC address
    		char * mac = &buffer[byte_iterator];
    		byte_iterator += 6;

    		char mac_str[18];
    		process_mac_address(mac, mac_str, connection);

    		// Extract and process application id
    		uint8_t appid_len = buffer[byte_iterator];
    		byte_iterator += 1;

    		if(appid_len == 0)
    		{
    			GVariant *signal_data;
    			signal_data = g_variant_new ("(ss)", src_addr_str, mac_str);
    			send_rcm_gdbus_signal("NewConnection", signal_data);
        		curr_length += pkt_len;
    			continue;
    		}

    		const uint8_t *app_raw = &buffer[byte_iterator];
    		byte_iterator += appid_len;
    		char *app_id = process_appid(appid_len, app_raw, connection);

    		// Extract opcode and act correspondingly
    		uint8_t op = buffer[byte_iterator];
    		byte_iterator += 1;
    		DBG("Processing %s command\n", code_to_str(op));

    		set_new_wait_code(connection, app_id, op);
    		switch (op)
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
    			send_rcm_gdbus_signal("RcvRequest", g);

    			remote_cmd_set_discovery_filter(connection, app_id, default_adapter, uuid_list);
    			break;
    		}
    		case REMOTE_CMD_START_DISCOVERY:
    		{
    			g = g_variant_new ("(ss)",
    					code_to_str(REMOTE_CMD_START_DISCOVERY),
						addr_port_str);
    			send_rcm_gdbus_signal("RcvRequest", g);

    			remote_cmd_start_discovery(connection, app_id, default_adapter);
    			break;
    		}
    		case REMOTE_CMD_CONNECT_DEVICE:
    		{
    			gettimeofday(&tv_send, NULL);

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

    			if(is_remote)
    			{
    				gchar *addr_code = g_strdup_printf ("%s\t%s", addr_str, code_to_str(REMOTE_CMD_CONNECT_DEVICE));
    				g = g_variant_new ("(ss)", addr_code, addr_port_str);
        			send_rcm_gdbus_signal("RcvRequest", g);
    				g_free(addr_code);

    				device_connect(connection, default_adapter, addr_bt, addr_type, cache_updated);
    			}
    			else
    			{
    				//Device is already connected locally, add to connected_device_list directly
    				struct btd_device *device = btd_adapter_find_device(default_adapter, &addr_bt, addr_type);
    				ConnectedDeviceData *connected_dev_data = create_connected_device_data(default_adapter, device, connection, cache_updated, false);
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

    			struct btd_device *device = btd_adapter_find_device(default_adapter, &addr_bt, addr_type);
    			ConnectedDeviceData *connected_dev_data = get_device_in_connected_device_list(device);
    			if(connected_dev_data)
    				remove_client_from_connected_device(connected_dev_data, connection);
    			break;
    		}
    		case REMOTE_CMD_STOP_DISCOVERY:
    		{
    			g = g_variant_new ("(ss)",
    					code_to_str(REMOTE_CMD_STOP_DISCOVERY),
						addr_port_str);
    			send_rcm_gdbus_signal("RcvRequest", g);

    			// Reinitialize the advertisement counter
    			RemoteClient *remote_client = get_remote_client_by_app_id(connection, app_id);
    			if(remote_client->nb_advertisements > 0)
    			{
    				remote_client->nb_advertisements = 0;
    			}

    			break;
    		}
    		case REMOTE_CHAR_WRITE:
    		{
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
    			byte_iterator += CHAR_VALUE_LEN;
    			DBG("[REMOTE_CHAR_WRITE] check the value length = %d\n", value_len);


    			uint8_t *value = &buffer[byte_iterator];

    			g_printf("value = ");
    			for (int i = 0; i < value_len; ++i)
    			{
    				g_printf("%02x", value[i]);
    			}
    			//		memcpy(value, &buffer_query[len], value_len);
    			gchar *gvar_msg_str = g_strdup_printf ("%s characteristic path: %s, value: %s", code_to_str(REMOTE_CHAR_WRITE), char_path, value);
    			g = g_variant_new ("(ss)",gvar_msg_str, addr_port_str);
    			send_rcm_gdbus_signal("RcvRequest", g);
    			g_free(gvar_msg_str);

    			write_characteristic(connection, char_path, value_len, value, default_adapter);
    			break;
    		}
    		case REMOTE_CMD_GET_MAC:
    		{
    			// For the moment, we never gets here because the function will break on appid_len == 0
    			break;
    		}
    		default:
    			DBG("Unknown command %d\n", op);
    			break;
    		}

    		curr_length += pkt_len;
    	}
    	g_free(addr_port_str);
    	g_free(src_addr_str);
    }
	return TRUE;
}

void make_active_clients_gvariant( ActiveConnection	*connection,
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

static void get_active_clients(void *g_v_builder)
{
    TRACE_FUNCTION;

	g_slist_foreach(c_connections, (GFunc)make_active_clients_gvariant, g_v_builder);

	// Offline testing only!
/*
	GVariantBuilder *g_var_builder = g_v_builder;

	for(int i=0; i<5; i++)
	{
		gchar * string = g_strdup_printf ("%s%d,%s%d", "MAC_ADDRESS", i, "IP_ADDRESS", i);
		g_variant_builder_add (g_var_builder, "s", string);
		g_free(string);
	}
*/
}

static void print_element( ActiveConnection	*connection,
						   gpointer user_data)
{
    TRACE_FUNCTION;
	g_printf("List elements: port = %d, connection = %p\n",
			get_connection_port(connection->connection), connection->connection);
}

static void print_connection( GSocketConnection	*connection)
{
    TRACE_FUNCTION;
	GSocketAddress *sockaddr = g_socket_connection_get_remote_address(connection, NULL);
	GInetAddress *addr = g_inet_socket_address_get_address(G_INET_SOCKET_ADDRESS(sockaddr));
	guint16 port = g_inet_socket_address_get_port(G_INET_SOCKET_ADDRESS(sockaddr));
	DBG("New Connection from %s:%d\n", g_inet_address_to_string(addr), port);
/*
	GVariant *signal_data;
	signal_data = g_variant_new ("(sq)", g_strdup_printf ("%s", g_inet_address_to_string(addr)), port);
	send_rcm_gdbus_signal("NewConnection", signal_data);*/
}

//HUI
ActiveConnection *create_active_connection( GSocketConnection	*connection)
{
    TRACE_FUNCTION;
    ActiveConnection *c_connection = malloc(sizeof(ActiveConnection));
    c_connection->mac_address = NULL;
    c_connection->connection = connection;
    c_connection->remote_clients = NULL;
    c_connection->authorized_devices = NULL;

    return c_connection;
}

void ask_for_mac(GSocketConnection * connection)
{
    TRACE_FUNCTION;
	// Craft a packet with the special code
	size_t data_size = 0;
//	uint8_t buffer_reply[SPECIAL_RQ_SIZE];
	uint8_t *buffer_reply = malloc(REPLY_HEADER_SIZE);

	buffer_reply[data_size] = REMOTE_CMD_GET_MAC;
	data_size += REPLY_HEADER_SIZE;

	// Send it to the client
	send_packet(connection, REMOTE_CMD_GET_MAC, buffer_reply, data_size);
	free(buffer_reply);
}

static int find_ip( ActiveConnection *active_conn,
					GInetAddress *ip_addr)
{
	GSocketAddress *socket_addr = g_socket_connection_get_remote_address(active_conn->connection, NULL);
	GInetAddress *active_ip_addr = g_inet_socket_address_get_address(G_INET_SOCKET_ADDRESS(socket_addr));
	return g_inet_address_equal(active_ip_addr, ip_addr) ? 0 : 1;
}

GSList * find_connected_client_ip(GSList *connections, GSocketConnection *connection)
{
	GSocketAddress *socket_addr = g_socket_connection_get_remote_address(connection, NULL);
	GInetAddress *client_addr = g_inet_socket_address_get_address(G_INET_SOCKET_ADDRESS(socket_addr));

	return g_slist_find_custom(connections, client_addr, (int (*)(gconstpointer, gconstpointer)) find_ip);
}

// This function will get called everytime a client attempts to connect
gboolean callback_connect( GThreadedSocketService	*service,
						   GSocketConnection		*connection,
						   GObject          		*source_object,
						   gpointer            		 user_data)
{
    TRACE_FUNCTION;
    GError * error = NULL;

    print_connection(connection);

    GSList *found = find_connected_client_ip(c_connections, connection);
    if(found) return FALSE;
    //HUI
    ActiveConnection *c_connection = create_active_connection(connection);
    c_connections = g_slist_append(c_connections, c_connection);

    DBG("connected_device_list length = %d\n", g_slist_length(connected_device_list));

    g_slist_foreach(c_connections, (GFunc)print_element, NULL);

    // Install watch
    g_object_ref(connection); // ADDED
    GSocket * socket = g_socket_connection_get_socket(connection);

    //Disable TCP aggregation
    GError *error_opt = NULL;
    g_socket_set_option(socket, IPPROTO_TCP, TCP_NODELAY, 1, &error_opt);

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
    if (!g_io_add_watch(channel, G_IO_IN | G_IO_HUP, callback_read, connection))
    {
        g_error("Cannot watch\n");
        return TRUE;
    }

    // Get the client's MAC address
    // Authentication procedures may be run here instead
    // We use MAC address because it's easy to get and because the security part
    // is out of scope of our current work on this PoC
    ask_for_mac(connection);
    return FALSE;
}

void configure_threaded_socket()
{
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
					 G_CALLBACK(callback_connect),
					 NULL);

	// Start the socket service
	g_socket_service_start((GSocketService*)service);

	// Run the main loop (it is the same as the bluez's one, so it is already run)
	DBG("Listening on port number %d\n", PORT);
}
/*
// This function will get called everytime a client attempts to connect
gboolean incoming_callback(GSocketService    * service,
						   GSocketConnection * connection,
						   GObject           * source_object,
						   gpointer            user_data)
{
    GError * error = NULL;
    // Get GInputStream
    g_print("Received Connection from client!\n");
    GInputStream * istream = g_io_stream_get_input_stream(G_IO_STREAM(connection));

}
*/
void configure_socket()
{
    TRACE_FUNCTION;
	// socket()
	GError * error = NULL;
	GSocketService * service = g_socket_service_new();

	g_socket_listener_add_inet_port((GSocketListener *) service,
									PORT,
									NULL,
									&error);

	if (error) g_error (error->message);

	// connect()
	// Listen to the 'incoming' signal
	g_signal_connect(service,
					 "incoming",
					 G_CALLBACK(callback_connect),
					 NULL);

	// Start the socket service
	g_socket_service_start(service);
}

void initialize_proxy_filter( void	*user_data)
{
	trigger_new_discovery(default_adapter);
	/* Offline testing
	for(uint8_t i=0; i<5; i++)
	{
		gchar *string_name = g_strdup_printf("Device%d", i);
		gchar *string_addr = g_strdup_printf("Address%d", i);

		GVariant *g = g_variant_new ("(ssqb)", string_name, string_addr, 1, i);
		send_rcm_gdbus_signal("DeviceFound", g);
		g_free(string_name);
		g_free(string_addr);
	}*/
}

void open_the_door()
{
    TRACE_FUNCTION;
	configure_threaded_socket();
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
//	configure_threaded_socket();
	create_trace_file();
	open_trace_file();
	gdbus_config();

	adapter_device_found_cb_register(device_found);
	adapter_stop_discovery_cb_register(cmd_stop_discovery);
	device_connection_completed_cb_register(send_cache_info);
	proxy_stop_init_discovery_cb_register(stop_init_start_discovery);
	proxy_init_cb_register(initialize_proxy_filter); // Call StartDiscovery
	get_active_clients_cb_register(get_active_clients);
	// Initialize the queue
	g_async_queue_ref(output_queue);
	output_queue = g_async_queue_new();

	run_rcm_gdbus_server();

	return 0;
}

//HUI
static void free_allocated_memory(void)
{
    TRACE_FUNCTION;
	DBG("RCM: proxy closed, free allocated memory");
	if(c_connections)
	{
		g_slist_free_full(c_connections, (GDestroyNotify)clear_active_connection_data);
		g_slist_free(c_connections);
	}

	if(known_device_list)
	{
		g_slist_free_full(known_device_list, (GDestroyNotify)clear_known_device);
		g_slist_free(known_device_list);
	}

	if(connected_device_list)
	{
		g_slist_free_full(connected_device_list, (GDestroyNotify)clear_connected_device_data);
		g_slist_free(connected_device_list);
	}
}

static void rcm_proxy_exit(void)
{
    TRACE_FUNCTION;
	//HUI: Free memory
	free_allocated_memory();

    stop_rcm_gdbus_server();

    g_async_queue_unref(output_queue);

    g_socket_service_stop((GSocketService*)service);
    g_socket_listener_close((GSocketListener *)service);
 //   g_free(service);

    if(trace_file)
    {
    	fclose(trace_file);
    	free(path_to_trace);
    }

//	dbus_message_unref(msg);
//	dbus_message_unref(reply);
//	dbus_connection_close(dbus_connection);
//	close(socket_desc);
	//btd_unregister_adapter_driver(&my_driver);
}

BLUETOOTH_PLUGIN_DEFINE(rcm_proxy, VERSION,
		BLUETOOTH_PLUGIN_PRIORITY_LOW, rcm_proxy_init, rcm_proxy_exit)
