/*
 * rcm_structures.h
 *
 *  Created on: Jul 15, 2019
 *      Author: nemo
 */

#ifndef SERVER_BLUEZ_5_43_RCM_STRUCTURES_H_
#define SERVER_BLUEZ_5_43_RCM_STRUCTURES_H_

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

static bool send_scan_results = true; // XXX Temporary for debugging !!! Should be removed
static gboolean can_send = TRUE;
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
static bool discovery_is_running = false;

// Remote clients ---------------------------------------------------------------------
// Exists as a separate structure because of app_id only.
// app_id is a field in the packet so it wouldn't be so easy to remove this from proxy
// the client should also be modified...
typedef struct remote_client_application {
	char *app_id;
	uint8_t wait_for_reply; // the code of the message the client is waiting for reply to
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
}UserData;

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


// =================================================================================================
// Functions
// Creation
ConnectedDeviceData *rcm_create_connected_device_data( struct btd_adapter	*adapter,
													   struct btd_device	*device,
													   GSocketConnection 	*connection,
													   bool	 				 cache_updated,
													   bool					 is_remote);

KnownDevice *rcm_create_known_device( struct btd_adapter	*adapter,
								  	  struct btd_device		*device,
									  const bdaddr_t		*bdaddr,
									  uint8_t				 addr_type,
									  uint8_t				*value,
									  uint8_t				 value_len);

ActiveClient *rcm_create_active_client( GSocketConnection	*connection);

RemoteClientApplication *rcm_create_remote_client_app( GSocketConnection	*connection,
													   char					*app_id,
													   uint8_t				 appid_len);

// =================================================================================================
// Commands
void rcm_authorize_device(gchar *mac, ConfigEntry *filter_entry);

// =================================================================================================
// Getters
ConnectedDeviceData *get_device_in_connected_device_list( struct btd_device	*device);

KnownDevice *get_device_in_known_device_list( struct btd_device	*device);

ActiveClient *get_client_by_connection_id( GSocketConnection	*connection);

ActiveClient *get_client_by_mac_addr( char	*mac_addr);

ActiveClient *get_client_by_remote_app( RemoteClientApplication	*remote_client_application);

RemoteClientApplication *get_remote_app_by_app_id( GSocketConnection	*connection,
										   	   	   char					*app_id);

GSList *get_client_by_code( uint8_t	reply_code);

guint16 rcm_get_connection_port( GSocketConnection	*connection);

char *get_connection_addr( GSocketConnection		*connection);

void rcm_get_client_filter(gchar *mac, void *g_v_builder)

// Printing
void print_element( ActiveClient	*connection,
 				    gpointer		 user_data);

//void print_fd(GSocketConnection *conn, const char *func);

//void print_mapping_element(BTAddrMapping *element);

/*// Helpers
int find_mapping_real(gconstpointer a, gconstpointer b);
int find_mapping_virt(gconstpointer a, gconstpointer b);
BTAddrMapping * map_address(const bdaddr_t *addr);
int connection_mapped(gconstpointer a, gconstpointer b);
void clean_mapping_element(BTAddrMapping *item);
*/
// =================================================================================================

#endif /* SERVER_BLUEZ_5_43_RCM_STRUCTURES_H_ */
