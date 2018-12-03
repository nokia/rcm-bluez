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

// Specific headers

#include <stdint.h>
#include <glib.h>
#include <stdlib.h>     // strtol
#include <string.h>     // memset	strlen
#include <ctype.h>      // isxdigit
#include <stdbool.h>    // bool

#include "bluetooth/bluetooth.h"    // needed by adapter.h
#include "bluetooth/sdp.h"          // needed by adapter.h

#include "lib/hci.h"
#include "lib/bluetooth.h"
#include "monitor/bt.h"

#include "complete_structures.h"
#include "src/gatt-client.h"
#include "dbus-server.c"

#include <errno.h>

// For socket management
#include <stdio.h>      // printf
#include <netinet/in.h>
#include <arpa/inet.h>  // inet_addr
#include <string.h>
#include "common.h" // SUCCESS, ERROR
#include <sys/socket.h>	// socket

#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

#include "config.h"
#include "limits.h"

#include <gio/gio.h>
#include <gio/gnetworking.h>

#include <sys/time.h> // For delay tracing

//#define HCI_MAX_EIR_LENGTH 						240
//#define BUFFER_REPLY_SIZE						HCI_MAX_EIR_LENGTH
#define BUFFER_REQUEST_SIZE						1500

typedef struct client_conn_t {
    GSocketClient     * client;     // Needed to get GSocketClient from main()
    GSocketConnection * connection; // Needed to return GSocketConnection to main()
    GIOChannel        * channel;
}ClientConnection;

ClientConnection *c = NULL;

// Let's try a structure to keep the informations needed for remote_connect
// The thing is that when we receive a reply for REMOTE_OP_CONNECT, the cache should be updated
// If it is already done, continue normally
// If it is not updated yet, keep the data in this structure until the cache is updated
typedef struct remote_connect
{
	struct btd_adapter *adapter;
	uint8_t server_reply[BUFSIZ];
}RemoteConnect;

RemoteConnect connect_data;

typedef struct pending_connect
{
	struct btd_device *device;
}PendingConnect;

PendingConnect pending_device;

typedef struct cache_file_download
{
	gchar dev_addr[18];
	uint32_t total_file_length;
	uint32_t written_bytes;
}CurrentFileDownload;

GSList *curr_downloads;

//GMainLoop * loop;
bool cache_updated = false;
bool pending_connection_query = false;
bool connect_le_called = false;
char device_addr[18]; // Address of a device we are trying to connect
struct btd_adapter *default_adapter;

//send pkt in queue
typedef struct pending_response{
	uint8_t *data_to_send;
	size_t data_len;
	guint16 port;
	GSocketConnection * connection;
}PendingResponse;

GAsyncQueue * output_queue;
static bool can_send = true;

// For tracing
FILE *trace_file;
struct timeval tv_send, tv_recv, tv_diff;
// End of tracing


static void init_pending_response(PendingResponse *response)
{
	response->connection = NULL;
	response->data_len = 0;
}
static void send_bytes_async(GSocketConnection * connection,
							 gpointer data,
							 gsize data_len,
							 GAsyncReadyCallback callback // Pass NULL to use the default callback 'callback_send_bytes_async' (see common.c)
							 );
static bool test = false;

static void on_remote_connection(struct btd_adapter *adapter, uint8_t *server_reply);

static void send_packet(gpointer data,
						int packet_size,
						uint8_t *packet_to_send);

static float tv2fl(struct timeval tv)
{
	TRACE_FUNCTION;
	return (float)(tv.tv_sec*1000.0) + (float)(tv.tv_usec/1000.0);
}

void write_trace()
{
	TRACE_FUNCTION;
	timersub(&tv_recv, &tv_send, &tv_diff);
	fprintf(trace_file, "%.6f %.6f %.6f ms %ld.%06ld %ld.%06ld %ld.%06ld mks\n", tv2fl(tv_send), tv2fl(tv_recv), tv2fl(tv_diff),
																					tv_send.tv_sec, tv_send.tv_usec, tv_recv.tv_sec, tv_recv.tv_usec,
																					tv_diff.tv_sec, tv_diff.tv_usec);

// Another way to do it
//	fprintf(trace_file, "temps en us: %ld us\n", ((tv_recv.tv_sec - tv_send.tv_sec) * 1000000 + tv_recv.tv_usec) - tv_send.tv_usec);
}

void connect_cb( void *data)
{
	TRACE_FUNCTION;
	struct btd_device *device = data;
	bool is_remote;
//	DBG("Inside the connect_cb function for the device = %s\n", device->name);

	const char *app_id = dbus_message_get_sender(device->connect);
	uint8_t appid_len = strlen(app_id);
	DBG("RCM: app_id %s\n", app_id);

	char addr[18];
	ba2str(&device->bdaddr, addr);

//	uint8_t message[BUFFER_REQUEST_SIZE];
	uint8_t *message = malloc(1 + appid_len + 1 + 1 + 1 + 1 + 1 + strlen(addr));
	size_t length = 0;

	message[length] = appid_len;
	length += 1;

	memcpy(&message[length], app_id, appid_len);
	length += appid_len;

	// Craft a request to connect a given device
	// [command code] [is_remote] [cache_updated] [bt addr type] [bt address size] [bt address value]
	message[length] = (uint8_t) REMOTE_CMD_CONNECT_DEVICE;
	length += 1;

	//HUI: tell proxy whether device is already connected with bluetooth
	if(device->from_bluetooth)
		is_remote = false;
	else
		is_remote = true;
	message[length] = is_remote;
	length += 1;

	if(device->from_bluetooth)
		cache_updated = true; //if device connected locally, no need cache file from proxy

	//HUI: adding a flag to let the proxy know whether it should send us a device cache file
	message[length] = cache_updated;
	length += 1;

	message[length] = device->bdaddr_type;
	length += 1;

	message[length] = strlen(addr);
	length += 1;

	memcpy(&message[length], addr, strlen(addr));
	length += strlen(addr);

	strcpy(device_addr, addr);

	send_packet(c, length, message);

	free(message);

	gettimeofday(&tv_send, NULL);
}

void disconnect_cb( void *data)
{
	TRACE_FUNCTION;
	struct btd_device *device = data;

	const char *app_id = device->owner;
	DBG("app_id = %s\n", app_id);
	uint8_t appid_len = strlen(app_id);

	char addr[18];
	ba2str(&device->bdaddr, addr);

	//	uint8_t message[BUFFER_REQUEST_SIZE];
	uint8_t *message = malloc(1 + appid_len + 1 + 1 + 1 + strlen(addr));
	size_t length = 0;

	message[length] = appid_len;
	length += 1;

	memcpy(&message[length], app_id, appid_len);
	length += appid_len;

	message[length] = (uint8_t) REMOTE_CMD_DISCONNECT_DEVICE;
	length += 1;

	message[length] = device->bdaddr_type;
	length += 1;

	message[length] = strlen(addr);
	length += 1;

	memcpy(&message[length], addr, strlen(addr));
	length += strlen(addr);

	strcpy(device_addr, addr);

	send_packet(c, length, message);
//	gettimeofday(&tv_send, NULL);
	free(message);

	device_set_owner_flag(device, NULL);
}

static void add_remote_device( struct btd_adapter	*adapter,
							   uint8_t				*server_reply,
							   gssize				 buffer_size)
{
	TRACE_FUNCTION;
	ssize_t len = REPLY_HEADER_SIZE;
	gboolean in_use;

	uint8_t addr_type = server_reply[len];
	len += 1;

	uint8_t addr_len = server_reply[len];
	len += 1;

	const uint8_t *addr = &server_reply[len];
	len += addr_len;

	char *addr_str = uint8_to_utf8(addr, addr_len, 18);

	//HUI +++++++++++++++++++++++++++++
	size_t eir_size = server_reply[len];
	len += 1;
	// +++++++++++++++++++++++++++++

	const uint8_t * eir = server_reply + len;
	len += eir_size;

	//if get IN_USE flag, set to true, else set to false
	if(len < buffer_size && server_reply[len] == 1)
		in_use = true;
	else
		in_use = false;

	bdaddr_t addr_bt;
	str2ba(addr_str, &addr_bt);

	update_remotely_found_devices(adapter,
								  &addr_bt,
								  addr_type, -55,
								  false, true,
								  false, eir,
								  eir_size,
								  in_use,
								  connect_cb);
}

static void discovery_stopped( uint8_t	*server_reply)
{
	TRACE_FUNCTION;
	uint8_t value = server_reply[1];
	switch(value)
	{
		case SUCCESS:
		{
			DBG("Discovery stopped\n");
			break;
		}
		case FAIL:
		{
			// Don't know what to do, it is not managed yet
			// For the moment only SUCCESS is sent
			DBG("Stop discovery failed\n");
			break;
		}
		default:
			DBG("Unknown command\n");
			break;
	}
}

static void receive_cache_info( uint32_t 	 received_part,
							    uint32_t 	 total_file_size,
							    char 		*local,
							    char 		*peer,
							    uint8_t 	*received_data,
							    const char 	*file_opentype,
							    uint32_t 	 total_written)
{
	TRACE_FUNCTION;
	char filename[PATH_MAX];
	snprintf(filename, PATH_MAX, STORAGEDIR "/%s/cache/%s", local, peer);

	FILE *received_file;

	received_file = fopen(filename, file_opentype);
	if (received_file == NULL)
	{
		DBG("Failed to open file foo --> %s\n", strerror(errno));
		fprintf(stderr, "Failed to open file for --> %s\n", strerror(errno));
		return;
//		exit(EXIT_FAILURE);
	}

	DBG("Receive %d bytes\n", received_part);
	display_reply_hex(received_part, received_data);

	size_t written = fwrite(received_data, sizeof(char), received_part, received_file);
	total_written += written;

	fclose(received_file);

	if(total_written == total_file_size)
	{
		if(cache_updated == false && pending_connection_query)
		{
			DBG("Cache updated\n");
			on_remote_connection(connect_data.adapter, connect_data.server_reply);
		}

		cache_updated = true;

		if(connect_le_called)
		{
			att_remote_connect_cb(NULL, NULL, pending_device.device);
			connect_le_called = false;
		}
	}
}

// Analog to pair_device_complete
// Not used
static void pair_device( void	*userdata)
{
	TRACE_FUNCTION;
	struct pair_device_data *data = userdata;
	struct mgmt_rp_pair_device *rp;

	rp->addr.bdaddr = data->bdaddr;
	rp->addr.type = data->addr_type;

	pair_remote_device_complete(rp, data);
}

static void on_remote_connection( struct btd_adapter	*adapter,
								  uint8_t				*server_reply)
{
	TRACE_FUNCTION;
	ssize_t len = REPLY_HEADER_SIZE;

	uint8_t addr_type = server_reply[1];
	len += 1;

	uint8_t addr_len = server_reply[2];
	len += 1;

	const uint8_t *addr = &server_reply[3];
	len += addr_len;

	char *addr_str = uint8_to_utf8(addr, addr_len, 18);

	char adapter_addr[18];
	ba2str(&adapter->bdaddr, adapter_addr);

	const uint8_t * eir = server_reply + len; // Shift the server reply by len bytes
	bdaddr_t addr_bt;
	str2ba(addr_str, &addr_bt); // XXX it seems that it needs more attention

	remotely_connected_device(addr_str,//&addr_bt,
							  addr_type,
							  eir,
							  HCI_MAX_EIR_LENGTH,
							  adapter);
}

static void remote_connect_le_called( void	*user_data)
{
	TRACE_FUNCTION;
	struct btd_device *device = user_data;
	connect_le_called = true;

//HUI: check if cache exists*************************************************************************
	const bdaddr_t *src, *dst;
	char srcaddr[18], dstaddr[18];
	char **keys, filename[PATH_MAX];
	GKeyFile *key_file;

	src = btd_adapter_get_address(device->adapter);
	ba2str(src, srcaddr);
	dst = device_get_address(device);
	ba2str(dst, dstaddr);

	snprintf(filename, PATH_MAX, STORAGEDIR "/%s/cache/%s", srcaddr, dstaddr);
	DBG("RCM DBG: cache filename =  STORAGEDIR = %s \"/%s/cache/%s\"", STORAGEDIR, srcaddr, dstaddr);

	key_file = g_key_file_new();
	g_key_file_load_from_file(key_file, filename, 0, NULL);
	keys = g_key_file_get_keys(key_file, "Attributes", NULL, NULL);
//**************************************************************************************************
	if(keys)
	{
		DBG("RCM: Cache file already exists, pending device, wait for connection reply from proxy\n");
//		att_remote_connect_cb(NULL, NULL, device);
		connect_le_called = false;
		cache_updated =true;
		pending_device.device = device;
	}
	else
	{
		// do nothing particular because the att_remote_connect_cb will be called when the cache is updated
		// Just keep the info about the device
		DBG("RCM: NO cache, pending device\n");
		pending_device.device = device;
		cache_updated =false;
	}

	g_strfreev(keys);
	g_key_file_free(key_file);
}

static void characteristic_write_cb( const  char		*sender,
									 	    char		*path,
										    int		 	 value_len,
										    uint8_t		*value,
									 struct btd_device	*device)
{
	TRACE_FUNCTION;

	const char *app_id = sender;
	uint8_t appid_len = strlen(app_id);

	// Let's cut a part of the path concerning the service and the characteristic only
	// the path is organized as follows: /org/bluez/hci{A}/dev_XX_XX_XX_XX_XX_XX/serviceYYYY/charZZZZ
	// As the part /org/bluez/hci{A}/dev_XX_XX_XX_XX_XX_XX may vary from one machine to another
	// we would only need this part: /serviceYYYY/charZZZZ

	//HUI send char_path as dev_XX_XX_XX_XX_XX_XX/serviceYYYY/charZZZZ
	char *adapter_path = default_adapter->path;
	int adapter_path_len = strlen(adapter_path);
	int N = strlen(path) - adapter_path_len;

	char characteristic_path[N];
	strncpy(characteristic_path, path + adapter_path_len, N);

	DBG("char path only = %s length = %d\n", characteristic_path, strlen(characteristic_path));

//	uint8_t message[BUFFER_REQUEST_SIZE];
	uint8_t *message = malloc(1 + appid_len + 1 + 1 + N + CHAR_VALUE_LEN + value_len);
	size_t length = 0;

	message[length] = appid_len;
	length += 1;

	memcpy(&message[length], app_id, appid_len);
	length += appid_len;

	message[length] = (uint8_t) REMOTE_CHAR_WRITE;
	length += 1;

	message[length] = N;
	length += 1;
//	DBG("[characteristic_write_cb] complete path = %s, %d - %d = %d = %d\n", path, strlen(path), device_path_len, strlen(characteristic_path), N);

	memcpy(&message[length], characteristic_path, N);
	length += N;

	message[length] = value_len;
	length += CHAR_VALUE_LEN;

	memcpy(&message[length], value, value_len);
	length += value_len;

	display_reply_hex(length, message);

	send_packet(c, length, message);

	free(message);
}

static int get_curr_file_download( gconstpointer a,
								   gconstpointer b)
{
	const CurrentFileDownload *el = a;
	const char *dev_addr = b;
	if(strcmp(el->dev_addr, dev_addr) == 0)
		return 0;
	return 1;
}


static void update_cache_info( struct btd_adapter	*adapter,
							   	   	  uint8_t		*server_reply,
									  gssize		 buf_len,
									  gchar			*context)
{
	TRACE_FUNCTION;
	char adapter_addr[18];
	ba2str(&adapter->bdaddr, adapter_addr);

	if(strcmp(context, "Start download") == 0)
	{
		gssize len = REPLY_HEADER_SIZE;

		uint32_t file_size;
		memcpy(&file_size, &server_reply[len], sizeof(file_size));
		len += sizeof(file_size);

		gsize received_part = buf_len - len;
		if(received_part < file_size)
		{
			CurrentFileDownload *curr_file = malloc(sizeof(CurrentFileDownload));
			strcpy(curr_file->dev_addr, device_addr);
			curr_file->total_file_length = file_size;
			curr_file->written_bytes = received_part;
			curr_downloads = g_slist_append(curr_downloads, curr_file);
			DBG("Expected file size = %d, received = %d bytes, written = %d bytes\n", file_size, received_part, curr_file->written_bytes);
		}
		DBG("adapter_addr = %s, device_addr = %s\n", adapter_addr, device_addr);
		receive_cache_info(received_part, file_size, adapter_addr, device_addr, &server_reply[len], "w", 0);
	}
	else if(strcmp(context, "Continue download") == 0)
	{
		GSList *curr_file = g_slist_find_custom(curr_downloads, device_addr, get_curr_file_download);
		if(!curr_file)
		{
			g_print("Something goes wrong... No file found\n");
			return;
		}
		CurrentFileDownload *file_data = curr_file->data;
		DBG("Continue download! Expected file size = %d, received = %d bytes\n", file_data->total_file_length, file_data->written_bytes);
		receive_cache_info(buf_len, file_data->total_file_length, adapter_addr, device_addr, server_reply, "a", file_data->written_bytes);
		file_data->written_bytes += buf_len;

		if(file_data->written_bytes == file_data->total_file_length)
		{
			curr_downloads = g_slist_remove(curr_downloads, file_data);
		}
	}
}

void set_remote_filter( 	  void	*user_data,
							  void	*discovery_filter,
						const void 	*sender)
{
	TRACE_FUNCTION;
	struct btd_adapter *adapter = user_data;
	struct discovery_filter *filter = discovery_filter;
	const char *app_id = sender;
	uint8_t appid_len = strlen(app_id);

	GSList *uuid_list = filter->uuids;
	guint uuid_num = 0;
	if(uuid_list != NULL)//If uuid_list is empty, do not send msg to proxy
	{
		uuid_num = g_slist_length(uuid_list); //the number of uuid in the list

		// 128 is the maximum length of an UUID, so it is temporary fixed in malloc
		// TODO: Ideally, the exact length of all UUID should be computed
		uint8_t *message = malloc(1 + appid_len + 1 + 1 + uuid_num*1 + uuid_num*128);
		size_t length = 0;

		message[length] = appid_len;
		length += 1;

		memcpy(&message[length], app_id, appid_len);
		length += appid_len;

		message[length] = (uint8_t) REMOTE_CMD_SET_FILTER;
		length += 1;

		DBG("Total number of uuid is %d\n", uuid_num);
		message[length] = uuid_num;
		length += 1;

		for(int i = 0; i < uuid_num; i++ )
		{
			gpointer uuid;
			uuid = g_slist_nth_data(uuid_list, i);
			uint8_t uuid_len = strlen(uuid);
			DBG("The %d uuid is %s, with the length of %d bytes\n", i, uuid, uuid_len);

			message[length] = uuid_len;
			length += 1;

			memcpy(&message[length], uuid, uuid_len);
			length += uuid_len;
		}

		send_packet(c, length, message);

		free(message);
	}
}

static void start_remote_scan( 		 void	*userdata,
							   const void	*sender)
{
	TRACE_FUNCTION;
	struct btd_adapter *adapter = userdata;
	const char *app_id = sender;
	uint8_t appid_len = strlen(app_id);

//	uint8_t message[BUFFER_REQUEST_SIZE];
	uint8_t *message = malloc(1 + appid_len + 1);
	size_t length = 0;

	//[appid_len][app_id][cmd]
	message[length] = appid_len;
	length += 1;

	memcpy(&message[length], app_id, appid_len);
	length += appid_len;

	message[length] = (uint8_t) REMOTE_CMD_START_DISCOVERY;
	length += 1;

	send_packet(c, length, message);

	free(message);
}

static void stop_remote_scan( 		void	*user_data,
							  const void	*sender)
{
	TRACE_FUNCTION;
	struct btd_adapter *adapter = user_data;
	const char *app_id = sender;
	uint8_t appid_len = strlen(app_id);

//	uint8_t message[BUFFER_REQUEST_SIZE];
	uint8_t *message = malloc(1 + appid_len + 1);
	size_t length = 0;

	//[appid_len][app_id][cmd]
	message[length] = appid_len;
	length += 1;

	memcpy(&message[length], app_id, appid_len);
	length += appid_len;

	message[length] = (uint8_t) REMOTE_CMD_STOP_DISCOVERY;
	length += 1;

	send_packet(c, length, message);

	free(message);
}

static void print_connection( GSocketConnection	*connection)
{
	TRACE_FUNCTION;
    GSocketAddress *sockaddr = g_socket_connection_get_remote_address(connection, NULL);
    GInetAddress *addr = g_inet_socket_address_get_address(G_INET_SOCKET_ADDRESS(sockaddr));
    guint16 port = g_inet_socket_address_get_port(G_INET_SOCKET_ADDRESS(sockaddr));
    DBG("Connection to %s:%d\n", g_inet_address_to_string(addr), port);
}

static void send_mac_address()
{
//	uint8_t message[SPECIAL_RQ_SIZE];
	uint8_t *message = malloc(1 + 1);
	size_t length = 0;

	// [appid_len][app_id][cmd]:
	// appid_len = 0, app_id not filed, cmd = REMOTE_CMD_GET_MAC
	message[length] = 0;
	length += 1;

	message[length] = (uint8_t) REMOTE_CMD_GET_MAC;
	length += 1;

	send_packet(c, length, message);

	free(message);
}

static gboolean callback_read( GIOChannel	*channel,
							   GIOCondition	 condition,
							   gpointer      user_data)
{
    TRACE_FUNCTION;
    gssize buffer_len;
    GIOStatus ret;
    GSocketConnection * connection = G_SOCKET_CONNECTION(user_data);
    GError            * error = NULL;

    if (condition & G_IO_HUP)
    {
        g_error("The server has closed the connection!\n");
        return FALSE;
    }

    gchar buffer[BUFSIZ];
    gsize bytes_read;
    GInputStream * istream = g_io_stream_get_input_stream(G_IO_STREAM(connection));
    buffer_len = g_input_stream_read(istream, buffer, BUFSIZ, NULL, &error);

    switch (buffer_len){
    case -1:
    	g_error("Error reading: %s\n", error->message);
    	g_object_unref(connection);
    	return FALSE;
    case 0:
    	g_print("Client disconnected\n");
    	return FALSE; // The client has closed the connection gracefully, remove this GSource
    default:
    	break;
    }

    if (buffer_len)
    {
    	DBG("Received %u bytes\n", buffer_len);//total length
    	// Display the reply
    	display_reply_hex(buffer_len, buffer);

    	//HUI
    	ssize_t length = 0;

    	while(length < buffer_len - 1)
    	{
        	ssize_t len = buffer[length];
        	length += 1;

        	// EIR
        	uint8_t code;
        	code = buffer[length];

        	switch(code)
        	{
        	case REMOTE_CMD_SET_FILTER:
        	{
        		//may have some feedback
        		break;
        	}
        	case REMOTE_CMD_START_DISCOVERY:
        	{
        		add_remote_device(default_adapter, &buffer[length], len);
        		//			struct eir_data eir_data;
        		//			eir_parse(&eir_data, eir, HCI_MAX_EIR_LENGTH);
        		//			DBG("%s\n",  eir_data.name);
        		//			g_slist_foreach(eir_data.services, print_iterator, "-->");
        		break;
        	}
        	case REMOTE_CMD_STOP_DISCOVERY:
        	{
        		discovery_stopped(&buffer[length]);
        		break;
        	}
        	case REMOTE_CMD_CONNECT_DEVICE:
        	{
        		gettimeofday(&tv_recv, NULL);
        		write_trace();
        		if(cache_updated)
        		{
        			on_remote_connection(default_adapter, &buffer[length]);
        			//HUI: new added
        			att_remote_connect_cb(NULL, NULL, pending_device.device);
        		}
        		else
        		{
        			pending_connection_query = true;
        			connect_data.adapter = default_adapter;
        			memcpy(&connect_data.server_reply, &buffer[length], len);
        		}
        		break;
        	}
        	case REMOTE_CMD_CACHE_INFO:
        	{
        		update_cache_info(default_adapter, &buffer[length], buffer_len - length, "Start download");
        		return TRUE;
        	}
        	case REMOTE_CMD_RELEASE:
        	{
        		break;
        	}
        	case REMOTE_CMD_GET_MAC:
        	{
        		send_mac_address();
        		break;
        	}
        	default:
        	{
        		// Unknown code, continue file download?!!!!!!!!!!!!!!!!!
        		update_cache_info(default_adapter, &buffer[length-1], buffer_len - length + 1, "Continue download");//rest parts of cache file, first byte is not length anymore
        		return TRUE;
        	}
        	}

        	length += len;

    	}
    }

    return TRUE;
}

void get_mac_address( unsigned char *mac_address)
{
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1)
	{ /* handle error*/ };

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { /* handle error */ }
    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) {
		strcpy(ifr.ifr_name, it->ifr_name);
		if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
			if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
			if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
					success = 1;
				break;
				}
			}
		}else
		{ /* handle error */ }
    }

//    unsigned char mac_address[6];
    if (success) {
    	memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);
    }

    for (int i = 0; i < 6; ++i)
    	printf("%02x:", mac_address[i]);
    printf("mac address %p\n", &mac_address);
}

static void callback_send_bytes_async( GObject      *source_object,
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
    DBG("written %d bytes \n", num_bytes_written);

    can_send = true;

    if (error)
    {
        g_error(error->message);
        return;
    }

    gpointer data = g_async_queue_try_pop(output_queue);
    DBG("pop from the queue: %p\n", data);
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
    free(pkt->data_to_send);
    g_free(pkt);
}

static void send_bytes_async(GSocketConnection * connection,
							 gpointer data,
							 gsize data_len,
							 GAsyncReadyCallback callback // Pass NULL to use the default callback 'callback_send_bytes_async' (see common.c)
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
static guint16 get_connection_port(GSocketConnection *connection)
{
	TRACE_FUNCTION;
	GSocketAddress *sockaddr = g_socket_connection_get_remote_address(connection, NULL);
	guint16 port = g_inet_socket_address_get_port(G_INET_SOCKET_ADDRESS(sockaddr));

	return port;
}
//**********************************

static void send_packet( gpointer	 data,
						 int		 packet_size,
						 uint8_t	*packet_to_send)
{
	TRACE_FUNCTION;
	struct timeval tv_test;
	gettimeofday(&tv_test, NULL);
	ClientConnection *c = data;

	if(c == NULL) return;

//********************************************
	unsigned char mac_address[6];
	get_mac_address(mac_address);
	printf("[send_packet] mac_address =");
	for (int i = 0; i < 6; ++i)
    	printf("%02x:", mac_address[i]);
	printf("\n");
//*******************************************

	uint8_t *message = malloc(packet_size + 6 + 1);
	size_t length = 0;

	message[length] = 6 + packet_size + 1;
	length += 1;

	memcpy(&message[length], mac_address, 6);
	length += 6;

	memcpy(&message[length], packet_to_send, packet_size);
	length += packet_size;

	//**********************
	if(!can_send) // channel is busy, enqueue it for later
	{
		DBG("Can't send, the socket is busy, push it in the queue\n");
		PendingResponse *pkt = malloc(sizeof(PendingResponse));
		init_pending_response(pkt);
		pkt->connection = c->connection;
		pkt->data_len = length;
		guint16 p = get_connection_port(c->connection);
		pkt->port = p;
		pkt->data_to_send = malloc(length);
		memcpy(pkt->data_to_send, message, length);

		g_async_queue_push(output_queue, pkt);
	}
	else
	{
		//***********************

		if (g_socket_connection_is_connected(c->connection))
		{
			can_send = false;
			send_bytes_async(c->connection, message, length, NULL);
		}
		else
		{
			DBG("Not connected\n");
		}
	}
	free(message);
}

static void callback_connect( GObject      *source_object,
							  GAsyncResult *res,
							  gpointer      user_data)
{
	TRACE_FUNCTION;
	GError * error = NULL;

	// Set GSocketConnection
	ClientConnection * c = (ClientConnection *) user_data;
	GSocketConnection * connection = g_socket_client_connect_to_host_finish(c->client, res, &error);
	if (error)
	{
		g_error(error->message);
		return;
	}

	c->connection = connection;

	print_connection(connection);

	// Install watch
	g_object_ref(connection); // ADDED
	GSocket * socket = g_socket_connection_get_socket(connection);

	if (!socket)
	{
		g_error("Cannot get socket\n");
		return;
	}

    //Disable TCP aggregation
    GError *error_opt = NULL;
    g_socket_set_option(socket, IPPROTO_TCP, TCP_NODELAY, 1, &error_opt);

	// From here, the code is the same in the client and the server.
	gint fd = g_socket_get_fd(socket);
	GIOChannel * channel = g_io_channel_unix_new(fd);
	c->channel = channel; // We'll need it for callback_send

	if (!channel)
	{
		g_error("Cannot create channel\n");
		return;
	}

	// Exchange binary data with the server
	g_io_channel_set_encoding(channel, NULL, &error);
	if (error)
	{
		g_error("Cannot set encoding: %s", error->message);
		return;
	}

	// G_IO_IN: There is data to read.
	// G_IO_OUT: Data can be written (without blocking).
	// G_IO_PRI: There is urgent data to read.
	// G_IO_ERR: Error condition.
	// G_IO_HUP: Hung up (the connection has been broken, usually for pipes and sockets).
	// G_IO_NVAL: Invalid request. The file descriptor is not open.

	// Triggered whenever the client can read data from the socket
	if (!g_io_add_watch(channel, G_IO_IN  | G_IO_HUP, callback_read, connection))
	{
		g_error("Cannot watch\n");
		return;
	}

	DBG("callback_connect OK!\n");

	GVariant *g = g_variant_new ("(s)", "Successfully connected to RCM Proxy\n");
	send_rcm_gdbus_signal("ConnectionStatus", g);
}

static void configure_and_run_main_loop( void	*userdata)
{
	TRACE_FUNCTION;

#if !GLIB_CHECK_VERSION(2, 35, 0)
	g_type_init ();
#endif

	struct connection *conn_info = userdata;
	guint16 port = atoi(conn_info->port);

	c = g_malloc0(sizeof *c);
	c->client = g_socket_client_new();
	g_socket_client_set_socket_type(c->client, G_SOCKET_TYPE_STREAM);

//	GMainLoop * loop = g_main_loop_new(NULL, FALSE);
	g_socket_client_connect_to_host_async(c->client, conn_info->ip_address, port, NULL, callback_connect, c);
//	g_main_loop_run(loop);
}

static void create_and_open_trace_file()
{
	// Let's create a file where we will keep tracing
	const char* dir = "./result_traces/";
	const char* file_name = "connection_delay_trace";
	const size_t path_size = strlen(dir) + strlen(file_name) + 1;
	char* path = malloc(path_size);

	if(path)
	{
		snprintf(path, path_size, "%s%s", dir, file_name);
		trace_file = fopen(path, "a+b"); // Open for read, write and create the file if necessary
		free(path);
	}

	if(!trace_file)
	{
		DBG("Failed to open the trace file ! %s%s\n", dir, file_name);
		exit(1);
	}
	else
	{
		DBG("Trace file is successfully opened!\n");
	}
}

//unsigned int id = 0;
static int rcm_client_probe( struct btd_adapter	*adapter)
{
	TRACE_FUNCTION;
	default_adapter = adapter;

	adapter_set_discovery_filter_cb_register(set_remote_filter);
	adapter_discovering_cb_register(start_remote_scan);
	adapter_stop_discovery_cb_register(stop_remote_scan);
	adapter_pairing_cb_register(pair_device);
	cache_update_cb_register(remote_connect_le_called);
	//HUI
	adapter_local_connected_cb_register(connect_cb);
	adapter_disconnect_cb_register(disconnect_cb);
	char_write_cb_register(characteristic_write_cb);
	rcm_connection_cb_register(configure_and_run_main_loop);

//	configure_and_run_main_loop("192.168.1.25"); // XXX Should be called when receive a DBus message SetProxyInformation
	return 0;
}

static void rcm_client_remove( struct btd_adapter	*adapter)
{
	TRACE_FUNCTION;
//    mgmt_unregister(adapter->mgmt, id);

    //    	g_main_loop_quit(loop);
    if(c)
    {
	g_io_stream_close(G_IO_STREAM(c->connection), NULL, NULL);
	g_object_unref(c->client);
    	g_object_unref(c->connection);
     }
    //    	g_main_loop_unref(loop);
    g_free(c);
	stop_rcm_gdbus_server();

    if(trace_file)
    	fclose(trace_file);
}

static struct btd_adapter_driver rcm_client_driver = {
	.name	= "Remote Connection Manager - Client part (RCM-c)",
	.probe	= rcm_client_probe,
	.remove	= rcm_client_remove,
};

static int rcm_client_init(void) {
	TRACE_FUNCTION;
	run_rcm_gdbus_server();
	create_and_open_trace_file();

	// Initialize the queue
	g_async_queue_ref(output_queue);
	output_queue = g_async_queue_new();

	return btd_register_adapter_driver(&rcm_client_driver);
}

static void rcm_client_exit(void) {
	TRACE_FUNCTION;
	btd_unregister_adapter_driver(&rcm_client_driver);
}

BLUETOOTH_PLUGIN_DEFINE(rcm_client, VERSION,
		BLUETOOTH_PLUGIN_PRIORITY_LOW, rcm_client_init, rcm_client_exit)
