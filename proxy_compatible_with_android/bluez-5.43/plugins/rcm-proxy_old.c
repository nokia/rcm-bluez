/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "src/plugin.h"
#include "config.h" // for STORAGEDIR
#include "limits.h" // for PATH_MAX
// Specific headers

#include <stdint.h>
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

//#include "adapter_static.c"
#include "complete_structures.h"
#include "dbus-server.c"

// For socket management
#include <stdio.h>
//#include <netinet/in.h>
#include <unistd.h>    //write
#include <arpa/inet.h> //inet_addr

//For dbus
//#include "gdbus/gdbus.h"

#include "eir_func.c"
#include "common.h"

#include <sys/sendfile.h>
#include <fcntl.h>

#include <sys/time.h>
//#include <glib.h>
//#include <gio/gio.h>

//#include <dbus/dbus.h>
//#include <dbus/dbus-glib.h>

#define BLUEZ_BUS_NAME "org.bluez"
#define BLUEZ_INTF_ADAPTER "org.bluez.Adapter1"
#define BLUEZ_INTF_DEVICE "org.bluez.Device1"
#define BLUEZ_INTF_CHAR "org.bluez.GattCharacteristic1"
#define NB_ADV_MAX 3

///////////////////////////
#define BUFFER_QUERY_SIZE 3000
#define BUFFER_REPLY_SIZE 3000

static DBusConnection *dbus_connection = NULL;

//static int socket_desc, client_sock;
static bool send_scan_results = true; // XXX Temporary for debugging !!! Should be removed

static bool sending_cache_info = false;
static char *connected_device_path;

// How many advertisements will be sent to the remote client
// there is no need to send all of them, the limited amount (even 1) is sufficient.
// We use 3 (cf. NB_ADV_MAX) by default to protect against the packet loss
static int nb_advertisements = 0;

// Tracing
static FILE *trace_file;
static char* path_to_trace;
static struct timeval tv_send, tv_recv, tv_diff;
// End of tracing

struct btd_adapter * default_adapter;
GMainLoop *loop;
GThreadedSocketService * service = NULL;

// GSocketConnection * c_connection;

static struct active_connections{
//	GInputStream* instream;
//	GOutputStream* ostream;
	guint16 port;
	GSocketConnection * connection; // socket connection corresponding to a given client
	uint8_t wait_for_reply; // the code of the message the client is waiting for reply to
};

GSList *c_connections = NULL;

static struct connect_user_data{
	bdaddr_t device_addr;
	uint8_t device_addr_type;
	struct btd_adapter * adapter;
};

// Quick implementation of the multi-client functionnality
// Trash coding part
static bool test = false;
static bool device_connected = false;
static bool device_is_known = false;
static bool discovery_is_running = false;
static struct known_device{
	bdaddr_t bdaddr;
	uint8_t addr_type;
	uint8_t buffer_reply[BUFFER_REPLY_SIZE];
	size_t data_size;
	uint8_t connection_reply[BUFFER_REPLY_SIZE];
	size_t connection_reply_len;
	struct bt_device *device;
};

static struct PendingResponse{
	uint8_t data_to_send[BUFSIZ];
	size_t data_len;
	guint16 port;
	GSocketConnection * connection;
};

GAsyncQueue * output_queue;
static bool can_send = true;

struct known_device known_dev;
// End of multiclient

static struct connect_user_data asked_device_data;
static bool discovery_started_remotely = false;

static void send_packet(uint8_t reply_code,
						gpointer data,
						gsize data_len);

struct active_connections *get_connection_by_code(uint8_t reply_code);
struct active_connections *get_connection_by_port(guint16 port);
static guint16 get_connection_port(GSocketConnection * connection);
static void send_bytes_async(GSocketConnection * connection,
							 gpointer data,
							 gsize data_len,
							 GAsyncReadyCallback callback // Pass NULL to use the default callback 'callback_send_bytes_async' (see common.c)
							 );
static void print_connection(GSocketConnection * connection);

static void init_pending_response(struct PendingResponse *response)
{
	response->connection = NULL;
	response->data_len = 0;
//	response->data_to_sent = NULL;
//	response->port = 0;
}

static void clear_pending_response(struct PendingResponse *response)
{
	if(response->connection) g_free(response->connection);
//	if(response->data_to_send) g_free(response->data_to_send);
}

static void destroy_response(struct PendingResponse *response)
{
	clear_pending_response(response);
	g_free(response);
}

static void callback_send_bytes_async(
    GObject      * source_object,
    GAsyncResult * res,
    gpointer       user_data
) {
    TRACE_FUNCTION;
    GError            * error = NULL;
    GSocketConnection * connection = user_data;
    GOutputStream     * ostream;
    gssize num_bytes_written;

    if(test)
    {
    	gettimeofday(&tv_recv, NULL);
    	printf("After sending CACHE + REMOTE_CMD_CONNECT_DEVICE reply, time = %ld.%06ld \n", tv_recv.tv_sec, tv_recv.tv_usec);
    	test = false;
    }

    ostream = g_io_stream_get_output_stream(G_IO_STREAM(connection));
    num_bytes_written = g_output_stream_write_bytes_finish(ostream, res, &error);

    can_send = true;

    if (error) {
        g_error(error->message);
        return;
    }

    gpointer data = g_async_queue_try_pop(output_queue);
    if(!data) return;

    struct PendingResponse *pkt = data;

    if (g_socket_connection_is_connected(pkt->connection))
    {
    	send_bytes_async(pkt->connection, &pkt->data_to_send, pkt->data_len, NULL);
    	test = true;
    }
    else
    {
    	g_print("Not connected\n");
    }

    g_free(pkt);
}

static void send_bytes_async(
    GSocketConnection * connection,
    gpointer data,
    gsize data_len,
    GAsyncReadyCallback callback // Pass NULL to use the default callback 'callback_send_bytes_async' (see common.c)
) {
    TRACE_FUNCTION;
    can_send = false;
    GOutputStream * ostream = g_io_stream_get_output_stream(G_IO_STREAM(connection));
    g_print("send_bytes_async(%p, %d):", data, data_len);
    print_hex(data, data_len);
    g_output_stream_write_async(
        ostream,
        data, data_len,
        0,
        NULL,
        callback ? callback : callback_send_bytes_async,
        connection
    );
}

static void create_trace_file()
{
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

static float tv2fl(struct timeval tv)
{
	return (float)(tv.tv_sec*1000.0) + (float)(tv.tv_usec/1000.0);
}

void write_trace()
{
	if(!trace_file)
		open_trace_file();

	timersub(&tv_recv, &tv_send, &tv_diff);
	fprintf(trace_file, "%.6f %.6f %.6f ms %ld.%06ld %ld.%06ld %ld.%06ld mks\n", tv2fl(tv_send), tv2fl(tv_recv), tv2fl(tv_diff),
																					tv_send.tv_sec, tv_send.tv_usec, tv_recv.tv_sec, tv_recv.tv_usec,
																					tv_diff.tv_sec, tv_diff.tv_usec);
// It is also correct
//	fprintf(trace_file, "temps en us: %ld us\n", ((tv_recv.tv_sec - tv_send.tv_sec) * 1000000 + tv_recv.tv_usec) - tv_send.tv_usec);
}

static void device_found(uint16_t index,
		   	   	   	   	 uint16_t length,
						 const void *param,
						 void *user_data)
{
	if(send_scan_results)
	{
		DBG("NATALYA my_plugin: Device found");
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
		DBG("Got an eir for new device, size = %d", eir_len);

		if (length != sizeof(*ev) + eir_len) {
			btd_error(adapter->dev_id,
					"Device found event size mismatch (%u != %zu)",
					length, sizeof(*ev) + eir_len);
			eir_data_free(&eir_data);
			return;
		}

		if (eir_len == 0)
		{
			printf("[my_plugin::device_found] EIR is NULL! \n");
			eir = NULL;
		}
		else
		{
			eir = ev->eir;
			eir_parse(&eir_data, eir, eir_len);
		}
		// Crafting the reply (header + data)
		size_t data_size = 0;
		uint8_t buffer_reply[BUFFER_REPLY_SIZE];

		size_t eir_size = eir_len;

		printf("Put code of the message we reply on, %s\n", code_to_str(REMOTE_CMD_START_DISCOVERY));
		buffer_reply[data_size] = REMOTE_CMD_START_DISCOVERY; // HEADER
		data_size = REPLY_HEADER_SIZE;

		buffer_reply[data_size] = ev->addr.type;
		data_size += 1;

		ba2str(&ev->addr.bdaddr, addr);
		buffer_reply[data_size] = strlen(addr);
		data_size += 1;

		memcpy(&buffer_reply[data_size], addr, strlen(addr));
		data_size += strlen(addr);

		memcpy(&buffer_reply[data_size], eir, eir_size);
		data_size += eir_size;

		gboolean passed = FALSE;
		// Send a packet via gio socket
		if((strcmp(addr, "F8:1D:78:60:3D:D9") == 0))
		{
			printf("Actually sending our packet through the GIO socket\n");
			passed = TRUE;
			GVariant *g = g_variant_new ("(ssb)", eir_data.name, g_strdup_printf ("%s", addr), passed);
			send_rcm_gdbus_signal("DeviceFound", g);

			if(nb_advertisements <= NB_ADV_MAX)
			{
				send_packet(REMOTE_CMD_START_DISCOVERY, &buffer_reply, data_size);
				nb_advertisements++;
				if(nb_advertisements == 1)
				{
					known_dev.addr_type = ev->addr.type;
					known_dev.bdaddr = ev->addr.bdaddr;
					memcpy(&known_dev.buffer_reply, &buffer_reply, data_size);
					known_dev.data_size = data_size;
					device_is_known = true;
				}
			}
		}
		if(!passed)
		{
			GVariant *g = g_variant_new ("(ssb)", eir_data.name, g_strdup_printf ("%s", addr), passed);
			send_rcm_gdbus_signal("DeviceFound", g);
		}
	}
}

static void gdbus_config()
{
	DBusError* error = NULL;

	printf("Getting DBus connection\n");
	dbus_connection = dbus_bus_get(DBUS_BUS_SYSTEM, error);

	if(error)
	{
		printf("Unable to get dbus connection %s\n", error->message);
	}
	printf("Got DBus connection %p\n", dbus_connection);

}

static void remote_cmd_start_discovery(struct btd_adapter *adapter)
{
	if(!device_is_known)
	{
		printf("Calling StartDiscovery through DBus, adapter id = %d\n", adapter->dev_id);
		send_scan_results = true;

		DBusMessage *msg = NULL; //, *reply;
		DBusMessage *reply;

		msg = dbus_message_new_method_call(BLUEZ_BUS_NAME,
				adapter->path,
				BLUEZ_INTF_ADAPTER,
				"StartDiscovery");
		DBG("DBus message pointer = %p", msg);
		gboolean ok = g_dbus_send_message(dbus_connection, msg);
		DBG("DBus message sent %d", ok);

		discovery_started_remotely = true;
		discovery_is_running = true;
	}
	else if(device_is_known)
	{
		printf("Device is already known by server thanks to the client 1, so no need to start discovery again\n");
		// We can answer to the client right now
		send_packet(REMOTE_CMD_START_DISCOVERY, &known_dev.buffer_reply, known_dev.data_size);
	}
//	dbus_message_unref(msg);
}

static void remote_cmd_stop_discovery(struct btd_adapter *adapter)
{
// TODO Check whether discovery has been started by an authorized client. If not, ignore.
	if(discovery_is_running)
	{
		send_scan_results = false;
		DBusMessage *msg = NULL; //, *reply;
		DBusMessage *reply;

		msg = dbus_message_new_method_call(BLUEZ_BUS_NAME,
				adapter->path,
				BLUEZ_INTF_ADAPTER,
				"StopDiscovery");
		DBG("DBus message pointer = %p", msg);
		gboolean ok = g_dbus_send_message(dbus_connection, msg);
		DBG("DBus message sent = %d", ok);

		// Reinitialize the advertisement counter
		if(nb_advertisements > 0)
			nb_advertisements = 0;
	}
	else
	{
		printf("Got StopDiscovery request but the discovery is not running\n");
	}
//	dbus_message_unref(msg);
}

static void cmd_stop_discovery(void *user_data)
{
	struct btd_adapter *adapter = user_data;
	// Here we should check whether the discovery has been started remotely
	// If so, send reply to the client. Otherwise : ignore.
	if(discovery_started_remotely)
	{
		discovery_started_remotely = false;

		size_t data_size = 0;
		uint8_t buffer_reply[BUFFER_REPLY_SIZE];

		printf("Put code of the message we reply on, %s\n", code_to_str(REMOTE_CMD_STOP_DISCOVERY));
		buffer_reply[data_size] = REMOTE_CMD_STOP_DISCOVERY; // HEADER
		data_size = REPLY_HEADER_SIZE;

		buffer_reply[data_size] = SUCCESS;
		data_size += 1;
		discovery_is_running = false;
	}
}

static void send_cache_info(void *userdata)
{
	sending_cache_info = true;
	struct btd_device *device = userdata;
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
			printf("Error opening file --> %s", strerror(errno));
			fprintf(stderr, "Error opening file --> %s", strerror(errno));
			return;
			//		exit(EXIT_FAILURE);
		}
		/* Get file stats */
		if (fstat(fd, &file_stat) < 0)
		{
			printf("Error fstat --> %s", strerror(errno));
			fprintf(stderr, "Error fstat --> %s", strerror(errno));
			return;
			//		exit(EXIT_FAILURE);
		}

		fprintf(stdout, "File Size: \n%d bytes\n", file_stat.st_size);
		sprintf(file_size, "%d", file_stat.st_size);

		printf("Sending file size = %s\n", file_size);

		printf("Now we should send the file\n");

		FILE *fp;
		uint32_t lSize;

		fp = fopen ( filename , "r" );
		if(!fp)
		{
			printf("Error opening file --> %s", strerror(errno));
			fprintf(stderr, "Error opening file --> %s", strerror(errno));
			return;
		}
		fseek( fp , 0L , SEEK_END);
		lSize = ftell( fp );
		rewind( fp );

		// allocate memory for entire content
		char file_buffer[lSize+1];
		//file_buffer = calloc( 1, lSize+1 );
		if(!file_buffer)
		{
			fclose(fp);
			fprintf(stderr, "Memory allocation fails --> %s", strerror(errno));
			return;
		}
		// copy the file into the buffer
		if(1!=fread( file_buffer , lSize, 1 , fp))
		{
		  fclose(fp);
		  free(file_buffer);
		  fputs("entire read fails",stderr);
		  return;
		}

		printf("Sending file size lSize = %d = file_size = %s\n", lSize, file_size);
		/* Crafting the packet */
		uint8_t buffer_reply[BUFSIZ];
		ssize_t data_size = 0;

		printf("Put code of the message we are sending, %s\n", code_to_str(REMOTE_CMD_CACHE_INFO));
		buffer_reply[data_size] = REMOTE_CMD_CACHE_INFO; // HEADER
		data_size = REPLY_HEADER_SIZE;
		printf("data_size = %d\n", data_size);

		// Size of the file
		memcpy(&buffer_reply[data_size], &lSize, sizeof(lSize));
		data_size += sizeof(lSize);
		printf("data_size = %d\n", data_size);

		strncpy(&buffer_reply[data_size], file_buffer, lSize+1);

		data_size += lSize;
		printf("data_size = %d\n", data_size);

		// Actually send the file
		send_packet(REMOTE_CMD_CONNECT_DEVICE, buffer_reply, data_size);

		fclose(fp);
//		free(file_buffer);
}

static void connection_result(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	// Write the time where the connection is successfully established
	gettimeofday(&tv_recv, NULL);
	write_trace();

	const struct mgmt_ev_device_connected *ev = param;
	struct btd_adapter *adapter = user_data;
//	struct connect_user_data *conn_user_data = user_data;
	bdaddr_t asked_device_addr = asked_device_data.device_addr;
	uint8_t asked_addr_type = asked_device_data.device_addr_type;
//	struct btd_adapter *adapter = asked_device_data->adapter;
	char asked_device_address[18];

	struct btd_device *ev_device;
	uint8_t *eir;
	uint16_t ev_eir_len;
	char ev_device_addr[18];

	ev_eir_len = btohs(ev->eir_len);

	ba2str(&ev->addr.bdaddr, ev_device_addr);
	ba2str(&asked_device_addr, asked_device_address);

	ev_device = btd_adapter_find_device(adapter, &ev->addr.bdaddr,
			ev->addr.type);

	struct btd_device *test_device = btd_adapter_find_device(adapter, &asked_device_addr, asked_addr_type);

	if (!ev_device) {
		btd_error(adapter->dev_id,
				"Unable to get device object for %s, pointer = %p, test device = %p, address = %s", ev_device_addr, ev_device, test_device, asked_device_address);
		return;
	}
	else if(strcmp(ev_device_addr, asked_device_address) != 0)
	{
		printf("The connected device is not the asked one. Connected addr = %s Asked addr = %s\n",
				ev_device_addr, asked_device_address);
		return;
	}

	if (ev_eir_len == 0)
		eir = NULL;
	else
		eir = ev->eir;

	// Crafting the reply (header + data)
	size_t data_size = 0;
	uint8_t buffer_reply[BUFFER_REPLY_SIZE];

	size_t eir_size = ev_eir_len;

	printf("Put code of the message we reply on, %s\n", code_to_str(REMOTE_CMD_CONNECT_DEVICE));
	buffer_reply[data_size] = REMOTE_CMD_CONNECT_DEVICE; // HEADER
	data_size = REPLY_HEADER_SIZE;

	buffer_reply[data_size] = ev->addr.type;
	data_size += 1;

	buffer_reply[data_size] = strlen(ev_device_addr);
	data_size += 1;

	memcpy(&buffer_reply[data_size], ev_device_addr, strlen(ev_device_addr));
	data_size += strlen(ev_device_addr);
/*
	memcpy(&buffer_reply[data_size], eir_size, sizeof(uint16_t));
	data_size += sizeof(uint16_t);
*/
	memcpy(&buffer_reply[data_size], eir, eir_size);
	data_size += eir_size;
	send_packet(REMOTE_CMD_CONNECT_DEVICE, buffer_reply, data_size);

	device_connected = true;
	memcpy(&known_dev.connection_reply, &buffer_reply, data_size);
	known_dev.connection_reply_len = data_size;
	known_dev.device = ev_device;
}

static void device_connect(struct btd_adapter *adapter, const bdaddr_t bdaddr, uint8_t addr_type)
{
//	remote_cmd_stop_discovery(adapter); // STOP discovery, here or as a reaction on the corresponding remote command
	if(!device_connected)
	{
		char address_str[18];
		ba2str(&bdaddr, address_str);

		printf("CONVERTED FROM BDADDR to STR = %s \n", address_str);

		struct btd_device *device = btd_adapter_find_device(adapter, &bdaddr, addr_type);

		if(device == NULL)
		{
			printf("No Device found!!!\n");
		}

		printf("Calling \"Connect\" through DBus, adapter id = %d, device_path = %s\n",
				adapter->dev_id,
				device->path);

		asked_device_data.adapter = adapter;
		asked_device_data.device_addr = bdaddr;
		asked_device_data.device_addr_type = addr_type;

		adapter_connect_ev_cb_register(connection_result);

		// Start connection procedure
		DBusMessage *msg_connect = NULL;
		DBusMessage *reply;

		msg_connect = dbus_message_new_method_call(BLUEZ_BUS_NAME,
				device->path,
				BLUEZ_INTF_DEVICE,
				"Connect");

		gboolean ok_connect = g_dbus_send_message(dbus_connection, msg_connect);
		//	dbus_message_unref(msg_connect);
		DBG("DBus message sent = %d", ok_connect);
		connected_device_path = device->path; // XXX normally should be initialized where we are sure that the connection is successful

		gettimeofday(&tv_send, NULL);
	}
	else if(device_connected)
	{
		printf("Device is already connected, reply immediately\n");
		gettimeofday(&tv_recv, NULL);
		write_trace();

		send_packet(REMOTE_CMD_CONNECT_DEVICE, &known_dev.connection_reply, known_dev.connection_reply_len);
		gettimeofday(&tv_recv, NULL);
		printf("After sending REMOTE_CMD_CONNECT_DEVICE reply, time = %ld.%06ld \n", tv_recv.tv_sec, tv_recv.tv_usec);

		send_cache_info(known_dev.device);
	}
}

static void write_characteristic(char *char_path, uint8_t value_len, const uint8_t *value, struct btd_adapter *adapter)
{
/*	printf("[write_characteristic] value:\n");
	display_reply_hex(value_len, value);
*/
	// char_path may be different on different machines
	// At least the hci may not be the same
	int dev_path_len = strlen(connected_device_path);
	int char_path_len = strlen(char_path);

	int complete_path_len = dev_path_len + char_path_len;

	char complete_path[complete_path_len]; // complete path to the characteristic
	strcpy(complete_path, connected_device_path);
	strcat(complete_path, char_path);
	printf("Complete path = %s, length = %d, dev_path_len = %d, char_path_len = %d\n", complete_path, strlen(complete_path), dev_path_len, char_path_len);

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

	if(!dbus_message_iter_append_fixed_array(&array, DBUS_TYPE_BYTE, &value,
										value_len))
	{
		printf("Out of memory!\n");
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
	DBG("Char WriteValue DBus message sent = %d", ok);
}

static void send_packet(//GSocketConnection * connection,
						uint8_t reply_code,
						gpointer data,
						gsize data_len)
{
	TRACE_FUNCTION;

//	GSocketConnection * connection;
	// TODO Get connection corresponding to a reply code from the c_connections list
/*	printf("Sending packet for code = %s\n", code_to_str(reply_code));
	display_reply_hex(known_dev.data_size, &known_dev.buffer_reply);
*/
	struct active_connections *connection = get_connection_by_code(reply_code);
	guint16 port = get_connection_port(connection->connection);
	GSocketAddress *socket_addr = g_socket_connection_get_remote_address(connection->connection, NULL);
	GInetAddress *src_addr = g_inet_socket_address_get_address(G_INET_SOCKET_ADDRESS(socket_addr));
	guint16 src_port = g_inet_socket_address_get_port(G_INET_SOCKET_ADDRESS(socket_addr));


	if(!can_send)
	{
		// Create a PendingResponse element and push it to our output_queue
		printf("Can't send, the socket is busy, push it in the queue\n");
		struct PendingResponse *pkt = malloc(sizeof(struct PendingResponse));
		init_pending_response(pkt);
		pkt->connection = connection->connection;
		pkt->data_len = data_len;
		guint16 p = get_connection_port(connection->connection);
		pkt->port = p;
		memcpy(&pkt->data_to_send, data, data_len);

		g_async_queue_push(output_queue, pkt);
		return;
	}

	if (g_socket_connection_is_connected(connection->connection))
	{
		can_send = false; // XXX may be dangerous, it's like this just for trash coding tests :)
		send_bytes_async(connection->connection, data, data_len, NULL);
		GVariant *signal_data;
		signal_data = g_variant_new ("(ss)",
				    				 g_strdup_printf ("%s", code_to_str(reply_code)),
									 g_strdup_printf ("%s:%d", g_inet_address_to_string(src_addr), src_port));
		send_rcm_gdbus_signal("SendReply", signal_data);
	} else
	{
		g_print("callback_send : not connected\n");
	}
//	send_rcm_gdbus_signal(code_to_str(reply_code), signal_data);

	return; // We want to pull a single file.
}

static int cmp_connection_id(gconstpointer a, gconstpointer b)
{
	const struct active_connections *conn = a;
	const guint16 port = GPOINTER_TO_UINT(b);

	printf("Comparing connections: %d = %d \n", conn->port, port);
	return conn->port == port ? 0 : -1;
}

static int cmp_connection_code(gconstpointer a, gconstpointer b)
{
	const struct active_connections *conn = a;
	const uint8_t code = GPOINTER_TO_UINT(b);

	return conn->wait_for_reply == code ? 0 : -1;
}

struct active_connections *get_connection_by_code(uint8_t reply_code)
{
//cf btd_adapter_find_device
//adapter_id_cmp
	GSList *list;
	struct active_connections *connection;

	printf("Looking for connection waiting the reply for code = %s\n", code_to_str(reply_code));
	list = g_slist_find_custom(c_connections, GINT_TO_POINTER(reply_code),
								cmp_connection_code);
	if (!list)
	{
		printf("Corresponding connection wasn't found!\n");
		return NULL;
	}

	connection = list->data;

	return connection;
}

struct active_connections *get_connection_by_port(guint16 port)
{
	GSList *list;
	struct active_connections *connection;

	printf("Looking for connection waiting the reply for port = %d\n", port);
	list = g_slist_find_custom(c_connections, GINT_TO_POINTER(port),
								cmp_connection_id);
	if (!list)
	{
		printf("Corresponding connection wasn't found!\n");
		return NULL;
	}

	connection = list->data;

	return connection;
}

static guint16 get_connection_port(GSocketConnection * connection)
{
	GSocketAddress *sockaddr = g_socket_connection_get_remote_address(connection, NULL);
	guint16 port = g_inet_socket_address_get_port(G_INET_SOCKET_ADDRESS(sockaddr));

	return port;
}

static void set_new_wait_code(guint16 port, uint8_t new_code)
{
	struct active_connections *conn;
	printf("[set_new_wait_code] for connection on port = %d\n", port);
	conn = get_connection_by_port(port);
	printf("old code = %s\n", code_to_str(conn->wait_for_reply));
	conn->wait_for_reply = new_code;
	printf("new code = %s\n", code_to_str(conn->wait_for_reply));
}
//HUI
static void remote_cmd_set_discovery_filter(struct btd_adapter *adapter, GSList *uuid_list)
{
    TRACE_FUNCTION;
	//craft dbus msg include param(uuid..)
	printf("Calling SetDiscoveryFilter through DBus, adapter id = %d\n", adapter->dev_id);

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

}
static gboolean callback_read(GIOChannel    * channel,
							  GIOCondition    condition,
							  gpointer        user_data)
{
    TRACE_FUNCTION;
    gssize len;
    GIOStatus ret;
    GInputStream* instream = NULL;
    GSocketConnection * connection = G_SOCKET_CONNECTION(user_data);
    GError            * error = NULL;

    guint16 port = get_connection_port(connection);
    GSocketAddress *socket_addr = g_socket_connection_get_remote_address(connection, NULL);
    GInetAddress *src_addr = g_inet_socket_address_get_address(G_INET_SOCKET_ADDRESS(socket_addr));
    guint16 src_port = g_inet_socket_address_get_port(G_INET_SOCKET_ADDRESS(socket_addr));
    GVariant *g = NULL;
 //   printf("Get connection port = %d\n", port);

    if (condition & G_IO_HUP)
    {
        g_print("The client has disconnected! I feel alone so I stop to listen.\n");
        return FALSE; // The client has disconnected abruptly, remove this GSource
    }

    gchar buffer[BUFSIZ]; // Larger than sizeof(reply_t)
//    ret = g_io_channel_read_chars(channel, buffer, BUFSIZ, &len, &error);
    ret = g_io_channel_read_chars(channel, buffer, BUFSIZ, &len, &error);

    switch (ret)
    {
		case G_IO_STATUS_ERROR:
			g_error("Error reading: %s\n", error->message);
			g_object_unref(connection);
			return FALSE;
		case G_IO_STATUS_EOF:
			g_print("EOF\n");
			GVariant *signal_data;
			signal_data = g_variant_new ("(s)",g_strdup_printf ("%s:%d", g_inet_address_to_string(src_addr), port));
			send_rcm_gdbus_signal("ClientDisconnected", signal_data);
			return FALSE; // The client has closed the connection gracefully, remove this GSource
    }
/*
    instream = g_io_stream_get_input_stream(G_IO_STREAM(connection));
    len = g_input_stream_read (instream, buffer, BUFSIZ, NULL, &error);

    if(error)
    {
    	g_error("Cannot read from stream: %s", error->message);
    	return TRUE;
    }
*/
    if (len)
    {
    	// Parse the received message here
    	uint8_t op = buffer[0];
    	set_new_wait_code(port, op);
    	switch (op) {
    	case REMOTE_CMD_SET_FILTER:
    	{
    		DBG("Processing REMOTE_CMD_SET_FILTER command\n");
    		//filter_set = true;

    		//TODO create uuid_list from msg
    		uint8_t uuid_num = buffer[1];//the number of uuid in the msg
    		printf("The number of uuid is %d\n", uuid_num);

    		GSList *uuid_list = NULL;
    		uint8_t uuid_var[1500];
    		uint8_t uuid_len = buffer[2];//the length of first uuid
    		//   		char* uuid_pointer ;//pointer is pointing to the 1st uuid
    		gpointer *uuid_pointer = &buffer[3];

    		for(int i = 0; i < uuid_num; i++)
    		{
    			printf("The length of uuid is %d\n", uuid_len);
    			printf("Now uuid_pointer is pointing to %s\n", uuid_pointer);

    			char* uuid_str;
    			memcpy(uuid_var, uuid_pointer, uuid_len);
    			uuid_str = uint8_to_utf8(uuid_var, uuid_len, 36);

    			printf("uuid_var is %s\n", uuid_var);
    			printf("uuid_str is %s\n", uuid_str);

    			uuid_list = g_slist_append(uuid_list, uuid_str);
    			printf("uuid_list is %s\n", *uuid_list);

    			uuid_pointer = &buffer[3+uuid_len];
    			uuid_len = uuid_pointer[0];
    		}

    //		remote_cmd_set_discovery_filter(default_adapter, uuid_list);
    		break;
    	}
    	case REMOTE_CMD_START_DISCOVERY:
    	{
    		g = g_variant_new ("(ss)",
    						   code_to_str(REMOTE_CMD_START_DISCOVERY),
							   g_strdup_printf ("%s:%d", g_inet_address_to_string(src_addr), src_port));

    		printf("Processing REMOTE_CMD_START_DISCOVERY command\n");
    		remote_cmd_start_discovery(default_adapter);
    		break;
    	}
    	case REMOTE_CMD_CONNECT_DEVICE:
    	{
    		printf("Processing REMOTE_CMD_CONNECT_DEVICE command\n");
    		//		bdaddr_t addr;
    		//		str2ba("F8:1D:78:60:3D:D9", &addr);

    		ssize_t length = 1; // because the first byte is the command code

    		uint8_t addr_type = buffer[1];
    		length += 1;

    		uint8_t addr_len = buffer[2];
    		length += 1;

    		const uint8_t *addr = &buffer[3];
    		length += addr_len;

    		char *addr_str;
    		addr_str = uint8_to_utf8(addr, addr_len, 18);
    		printf("Connect a device matching the BT ADDRESS = %s\n", addr_str);

    		bdaddr_t addr_bt;
    		str2ba(addr_str, &addr_bt);
    		if(device_connected)
    		{
    			gettimeofday(&tv_send, NULL);
    		}

    		g = g_variant_new ("(ss)",
    						   g_strdup_printf ("%s\t%s", addr_str, code_to_str(REMOTE_CMD_CONNECT_DEVICE)),
							   g_strdup_printf ("%s:%d", g_inet_address_to_string(src_addr), src_port));

    		device_connect(default_adapter, addr_bt, addr_type);
    		break;
    	}
    	case REMOTE_CMD_STOP_DISCOVERY:
    	{
    		printf("Processing REMOTE_CMD_STOP_DISCOVERY command\n");

    		g = g_variant_new ("(ss)",
    						   code_to_str(REMOTE_CMD_START_DISCOVERY),
							   g_strdup_printf ("%s:%d", g_inet_address_to_string(src_addr), src_port));

    		remote_cmd_stop_discovery(default_adapter);
    		break;
    	}
    	case REMOTE_CHAR_WRITE:
    	{
/*    		printf("Processing REMOTE_CHAR_WRITE command\n");
    		printf("Received packet:\n");
    		display_reply_hex(len, buffer);
*/
    		// Let's look inside the packet
    		ssize_t length = 1; // start from the first byte (the 0th is a command code)

    		uint8_t path_len = buffer[length];
    		length += 1;

    		char* char_path;
    		const uint8_t *char_path_raw = &buffer[length];
    		length += path_len;
    		//Transform the binary to string
    		char_path = uint8_to_utf8(char_path_raw, path_len, path_len);
    		printf("[REMOTE_CHAR_WRITE] characteristic path = %s\n", char_path);

    		// Let's get the value and its length
    		uint8_t value_len = buffer[length];
    		length += 1;
    		printf("[REMOTE_CHAR_WRITE] check the value length = %d\n", value_len);

    		uint8_t *value = &buffer[length];//[value_len];
    		//		memcpy(value, &buffer_query[len], value_len);
    		g = g_variant_new ("(ss)",
    						   g_strdup_printf ("%s characteristic path: %s, value: %s",code_to_str(REMOTE_CHAR_WRITE), char_path, value),
							   g_strdup_printf ("%s:%d", g_inet_address_to_string(src_addr), src_port));

    		write_characteristic(char_path, value_len, value, default_adapter);
    		break;
    	}
    	default:
    		printf("Unknown command\n");
    		break;
    	}
	if(g != NULL)
	  send_rcm_gdbus_signal("RcvRequest", g);
    }

	return TRUE;
}

static void print_element(struct active_connections *connection, gpointer user_data)
{
	printf("List elements: port = %d, code = %s\n", connection->port,
													code_to_str(connection->wait_for_reply));
}

static void print_connection(GSocketConnection * connection)
{
	GSocketAddress *sockaddr = g_socket_connection_get_remote_address(connection, NULL);
	GInetAddress *addr = g_inet_socket_address_get_address(G_INET_SOCKET_ADDRESS(sockaddr));
	guint16 port = g_inet_socket_address_get_port(G_INET_SOCKET_ADDRESS(sockaddr));
	g_print("New Connection from %s:%d\n", g_inet_address_to_string(addr), port);

	GVariant *signal_data;
	signal_data = g_variant_new ("(s)",
			g_strdup_printf ("%s:%d", g_inet_address_to_string(addr), port));

	send_rcm_gdbus_signal("NewConnection", signal_data);
}

// This function will get called everytime a client attempts to connect
gboolean callback_connect(
    GThreadedSocketService    * service,
    GSocketConnection * connection,
    GObject           * source_object,
    gpointer            user_data
) {
    TRACE_FUNCTION;
    GError * error = NULL;

    // Print connection
    print_connection(connection);

    struct active_connections *c_connection = malloc(sizeof(struct active_connections));
    c_connection->connection = connection;
    c_connection->wait_for_reply = 0;	// For now the connection just started, we didn't receive any message from it yet
    c_connection->port = get_connection_port(connection);

    c_connections = g_slist_append(c_connections, c_connection);

    g_slist_foreach(c_connections, (GFunc)print_element, NULL);

    // Install watch
    g_object_ref(connection); // ADDED
    GSocket * socket = g_socket_connection_get_socket(connection);

    // From here, the code is the same in the client and the server.

    gint fd = g_socket_get_fd(socket);
    GIOChannel * channel = g_io_channel_unix_new(fd);

    if (!channel) {
        g_error("Cannot create channel\n");
        return TRUE;
    }

    // Exchange binary data with the client
    g_io_channel_set_encoding(channel, NULL, &error);
    if (error) {
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
    if (!g_io_add_watch(channel, G_IO_IN | G_IO_HUP, callback_read, connection)) {
        g_error("Cannot watch\n");
        return TRUE;
    }

    return FALSE;
}

static int rcm_proxy_probe(struct btd_adapter *adapter)
{
    TRACE_FUNCTION;
	default_adapter = adapter;

	return 0;
}

static void rcm_proxy_remove(struct btd_adapter *adapter)
{
    TRACE_FUNCTION;
//	g_main_loop_unref(loop);
	g_socket_service_stop((GSocketService*)service);
	g_free(service);

    if(trace_file)
    {
    	fclose(trace_file);
    	free(path_to_trace);
    }

    g_async_queue_unref(output_queue);
}

static struct btd_adapter_driver rcm_proxy = {
	.name = "Remote Connection Manager - Proxy part (RCM-p)",
	.probe = rcm_proxy_probe,
	.remove = rcm_proxy_remove,
};

static int rcm_proxy_init(void)
{
    TRACE_FUNCTION;

	btd_register_adapter_driver(&rcm_proxy);

	create_trace_file();
	open_trace_file();
	gdbus_config();

	adapter_device_found_cb_register(device_found);
	adapter_stop_discovery_cb_register(cmd_stop_discovery);
	device_connection_completed_cb_register(send_cache_info);
	// Initialize the queue
	g_async_queue_ref(output_queue);
	output_queue = g_async_queue_new();

#if !GLIB_CHECK_VERSION(2, 35, 0)
	g_type_init ();
#endif

	// socket()
	GError * error = NULL;
	service = (GThreadedSocketService*)g_threaded_socket_service_new(-1);

	g_socket_listener_add_inet_port((GSocketListener *) service,
									PORT,
									NULL,
									&error);

	if (error)
	{
		g_error(error->message);
		return 1;
	}

	// Listen to the 'incoming' signal
	g_signal_connect(service,
			"run",
			G_CALLBACK(callback_connect),
			NULL);

	// Start the socket service
	g_socket_service_start((GSocketService*)service);

	// Run the main loop (it is the same as the bluez's one, so it is already run)
	DBG("Listening on localhost:%d\n", PORT);

	//		loop = g_main_loop_new(NULL, FALSE);
	//		g_main_loop_run(loop);
	run_rcm_gdbus_server();
}

static void rcm_proxy_exit(void)
{
    TRACE_FUNCTION;
	stop_rcm_gdbus_server();

//	dbus_message_unref(msg);
//	dbus_message_unref(reply);
//	dbus_connection_close(dbus_connection);
//	close(socket_desc);
	//btd_unregister_adapter_driver(&my_driver);
}

BLUETOOTH_PLUGIN_DEFINE(rcm_proxy, VERSION,
		BLUETOOTH_PLUGIN_PRIORITY_LOW, rcm_proxy_init, rcm_proxy_exit)
