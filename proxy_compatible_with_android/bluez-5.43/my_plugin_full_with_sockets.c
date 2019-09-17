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

//#include <glib.h>
//#include <gio/gio.h>

//#include <dbus/dbus.h>
//#include <dbus/dbus-glib.h>

#define BLUEZ_BUS_NAME "org.bluez"
#define BLUEZ_INTF_ADAPTER "org.bluez.Adapter1"
#define BLUEZ_INTF_DEVICE "org.bluez.Device1"
#define BLUEZ_INTF_CHAR "org.bluez.GattCharacteristic1"

///////////////////////////
#define BUFFER_QUERY_SIZE 3000
#define BUFFER_REPLY_SIZE 3000

static DBusConnection *dbus_connection = NULL;

static int socket_desc, client_sock;
static bool send_scan_results = true; // XXX Temporary for debugging !!! Should be removed

static bool sending_cache_info = false;
static char *connected_device_path;

struct btd_adapter * default_adapter;
bool sockets = false;
GMainLoop *loop;
GSocketService * service;
GSocketConnection * c_connection;

static struct connect_user_data{
	bdaddr_t device_addr;
	uint8_t device_addr_type;
	struct btd_adapter * adapter;
};

static struct connect_user_data asked_device_data;
static bool discovery_started_remotely = false;

static void receive_cmd(struct btd_adapter *adapter);
static void send_packet(gpointer data,
						gsize data_len);

static void print_iterator(gpointer item, gpointer prefix) {
     printf("%s %s\n", (const char*) prefix, (const char *) item);
}

// The buffer must be pre-allocated and enough large
uint8_t * write_fake_eir(uint8_t * buffer, uint16_t * pbuffer_size) {
/*
    const char *buffer_query = "abcde";
    write(client_sock, buffer_query, strlen(buffer_query));
*/
	/////////////////////////

    struct eir_data eir_data;
    memset(&eir_data, 0, sizeof(eir_data));

    bdaddr_t addr;
    str2ba("C4:D9:87:C3:30:E3", &addr);

	// Craft the fake eir using the bluez structure
    // "%.8x-%.4x-%.4x-%.4x-%.8x%.4x"
    eir_data.services = g_slist_append(eir_data.services, "0000ffe5-0000-1000-8000-00805f9b34fb");
//    eir_data.services = g_slist_append(eir_data.services, "12345678-9abc-def0-0fed-cba987654321");
    eir_data.name = "Natalya-FAKE-LED";
    printf("name      = %s\n",  eir_data.name);
    g_slist_foreach(eir_data.services, print_iterator, "-->");

	// Make the corresponding EIR.
    //gpointer buffer = NULL;
    //uint16_t buffer_size = 0;
    buffer = to_eir(&eir_data, buffer, pbuffer_size);
    printf("EIR ready: @ = %p size = %d\n", buffer, *pbuffer_size);
    return buffer;
}

uint8_t * write_real_eir(uint8_t * buffer, uint16_t * pbuffer_size, const uint8_t * eir) {

	buffer = eir;
	printf("EIR ready: @ = %p size = %d\n", buffer, *pbuffer_size);
	return buffer;
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

		// get EIR from the packet
		if (length < sizeof(*ev)) {
			btd_error(adapter->dev_id,
					"Too short device found event (%u bytes)", length);
			return;
		}

		eir_len = btohs(ev->eir_len);
		DBG("Got an eir for new device, size = %d", eir_len);

		if (length != sizeof(*ev) + eir_len) {
			btd_error(adapter->dev_id,
					"Device found event size mismatch (%u != %zu)",
					length, sizeof(*ev) + eir_len);
			return;
		}

		if (eir_len == 0)
			eir = NULL;
		else
			eir = ev->eir;

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

		if(sockets)
		{
			write(client_sock, buffer_reply, data_size);
			receive_cmd(adapter);
		}
		else
		{
			// Send a packet via gio socket
			if(strcmp(addr, "F8:1D:78:60:3D:D9") == 0)
			{
				printf("Actually sending our packet through the GIO socket\n");
				send_packet(&buffer_reply, data_size);
			}
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
//	DBG("DBus message sent = %d", ok);

/*	reply = start_remote_discovery(dbus_connection, msg, adapter);
	if(!reply)
	{
		printf("MY_PLUGIN ERROR: No reply for START discovery call!!! \n");
	}
*/
	discovery_started_remotely = true;
	dbus_message_unref(msg);
}

static void remote_cmd_stop_discovery(struct btd_adapter *adapter)
{
	// TODO Check whether discovery has been started by the given client. If not, ignore.

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
/*	reply = stop_remote_discovery(dbus_connection, msg, adapter);
	if(!reply)
	{
		printf("MY_PLUGIN ERROR: No reply for STOP discovery call!!! \n");
	}
*/
	dbus_message_unref(msg);

//	gboolean ok = g_dbus_send_message(dbus_connection, msg);
//	DBG("DBus message sent = %d", ok);
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

		if(sockets)
		{
			//		write(client_sock, buffer_reply, data_size);
			receive_cmd(adapter); // Waiting for reply
		}
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

		if(sockets)
		{
			/* Crafting the packet */
			uint8_t buffer_reply[BUFFER_REPLY_SIZE];
			size_t data_size = 0;

			printf("Put code of the message we are sending, %s\n", code_to_str(REMOTE_CMD_CACHE_INFO));
			buffer_reply[data_size] = REMOTE_CMD_CACHE_INFO; // HEADER
			data_size = REPLY_HEADER_SIZE;

			// Size of the file :)
			buffer_reply[data_size] = strlen(file_size);
			data_size += 1;

			memcpy(&buffer_reply[data_size], file_size, strlen(file_size));
			data_size += strlen(file_size);

			// Send the file size
			send(client_sock, buffer_reply, data_size, 0);

			// File data will be sent separately with sendfile command
			off_t offset = 0;
			int remain_data;
			size_t sent_bytes = 0;

			remain_data = file_stat.st_size;

			/* Sending file data */
			printf("Sending the file data, len = %d\n", remain_data);
			while ((remain_data > 0))
			{
				sent_bytes = sendfile(client_sock, fd, &offset, BUFSIZ);
				printf("Sent bytes should be > 0 = %d\n", sent_bytes);
				if(sent_bytes > 0)
				{
					printf("1. Server sent %d bytes from file's data, offset is now : %d and remaining data = %d\n", sent_bytes, offset, remain_data);
					fprintf(stdout, "1. Server sent %d bytes from file's data, offset is now : %d and remaining data = %d\n", sent_bytes, offset, remain_data);
					remain_data -= sent_bytes;
					printf("2. Server sent %d bytes from file's data, offset is now : %d and remaining data = %d\n", sent_bytes, offset, remain_data);
					fprintf(stdout, "2. Server sent %d bytes from file's data, offset is now : %d and remaining data = %d\n", sent_bytes, offset, remain_data);
				}
				else if(sent_bytes < 0)
				{
					printf("ERROR: Sent bytes < 0!\n");
					return;
				}
			}

			sending_cache_info = false;

			receive_cmd(adapter);
		}
	else if(!sockets)
	{
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

		// 1 field: length of the file size
		// 2 field: file size
/*
		buffer_reply[data_size] = (uint32_t) strlen(file_size);
		data_size += sizeof(uint32_t);
		printf("data_size = %d\n", data_size);

		memcpy(&buffer_reply[data_size], file_size, strlen(file_size));
		data_size += strlen(file_size);
		printf("data_size = %d\n", data_size);
*/
		strncpy(&buffer_reply[data_size], &file_buffer, lSize+1);
/*
		// Test of file writing
				char filename_text[PATH_MAX];
				snprintf(filename_text, PATH_MAX, STORAGEDIR "/%s/cache/%s_test", local, peer);

				FILE *received_file;

				received_file = fopen(filename_text, "w");
				if (received_file == NULL)
				{
					printf("Failed to open file foo --> %s\n", strerror(errno));
					fprintf(stderr, "Failed to open file foo --> %s\n", strerror(errno));

					exit(EXIT_FAILURE);
				}
				char file_test[lSize+1];
				memcpy(&file_test, &buffer_reply[data_size], lSize+1);

				printf("FILE BUFFER\n");
				display_reply_hex(lSize+1, &file_buffer);
				printf("&buffer_reply[data_size]\n");
				display_reply_hex(lSize+1, &buffer_reply[data_size]);

				fputs(file_buffer, received_file);
				//size_t written = fwrite(&file_test, sizeof(char), lSize, received_file);
				//printf("File received, %d bytes written, let's close it\n", written);
				fclose(received_file);
		//
*/
		data_size += lSize;
		printf("data_size = %d\n", data_size);

		// Actually send the file
		send_packet(buffer_reply, data_size);

		fclose(fp);
//		free(file_buffer);

		/* Approximative algorithm
FILE *fp;
long lSize;
char *buffer;

fp = fopen ( "blah.txt" , "rb" );
if( !fp ) perror("blah.txt"),exit(1);

fseek( fp , 0L , SEEK_END);
lSize = ftell( fp );
rewind( fp );

// allocate memory for entire content
buffer = calloc( 1, lSize+1 );
if( !buffer ) fclose(fp),fputs("memory alloc fails",stderr),exit(1);

// copy the file into the buffer
if( 1!=fread( buffer , lSize, 1 , fp) )
  fclose(fp),free(buffer),fputs("entire read fails",stderr),exit(1);

fclose(fp);
free(buffer);
*/
		/*
			GFile * file = g_file_new_for_path(filename);
			GFileInputStream * istream = g_file_read(file, NULL, &error);
			send_file_async(c_connection, q->query_id, (GInputStream *) istream, NULL); // NULL or your own callback
		 */
	}
	//
	//	len = send(peer_socket, file_size, sizeof(file_size), 0);
}

static void connection_result(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
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

	if(sockets)
	{
		write(client_sock, buffer_reply, data_size);
	}
	else
	{
		send_packet(buffer_reply, data_size);
	}
	//For debug reasons I comment this
//	receive_cmd(adapter); // XXX!!!
}

static void device_connect(struct btd_adapter *adapter, const bdaddr_t bdaddr, uint8_t addr_type)
{
//	remote_cmd_stop_discovery(adapter); // STOP discovery, here or as a reaction on the corresponding remote command

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

/*
	mgmt_register(adapter->mgmt, MGMT_EV_DEVICE_CONNECTED,
								adapter->dev_id,
								connection_result,
								&user_data, NULL);
*/
	adapter_connect_ev_cb_register(connection_result);

	// Start connection procedure
	DBusMessage *msg_connect = NULL;
	DBusMessage *reply;

	msg_connect = dbus_message_new_method_call(BLUEZ_BUS_NAME,
									   device->path,
									   BLUEZ_INTF_DEVICE,
									   "Connect");

/*	reply = remote_dev_connect(dbus_connection, msg_connect, adapter);

	if(!reply)
	{
		printf("MY_PLUGIN ERROR: No reply for CONNECT device call!!! \n");
	}
*///	reply = dbus_connection_send_with_reply(dbus_connection, msg_connect, -1, NULL);

	gboolean ok_connect = g_dbus_send_message(dbus_connection, msg_connect);
	dbus_message_unref(msg_connect);
	DBG("DBus message sent = %d", ok_connect);
	connected_device_path = device->path; // XX normally should be initialized in place where we are sure that the connection is successful
}

static void write_characteristic(char *char_path, uint8_t value_len, const uint8_t *value, struct btd_adapter *adapter)
{
	printf("[write_characteristic] value:\n");
	display_reply_hex(value_len, value);

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

//	receive_cmd(adapter);  // We can't do it here because the while loop will block the execution of the characteristic_write_value in gatt_client

}

static void receive_cmd(struct btd_adapter *adapter)
{
	int read_size;
	uint8_t op;
	bool stop_loop = false;
	uint8_t buffer_query[BUFSIZ];

	printf("Waiting for a command...\n");

	// Receive a message from client
	while (!sending_cache_info)
	{
		read_size = recv(client_sock, buffer_query, BUFSIZ, 0);
		printf("read_size = %zu\n", (size_t) read_size);

		if(read_size > 0)
		{
				// Parsing the query
			/*		uint16_t size = buffer_query[0]; // TODO ntohs
		if (size != 2) {
			printf("Invalid size (%zu), message discarded\n", (size_t) size);
			continue;
		}*/
			op = buffer_query[0]; // TODO ntohs
			printf("Got %s command\n", code_to_str(op));

			switch (op) {
			case REMOTE_CMD_START_DISCOVERY:
			{
				stop_loop = true;
				send_scan_results = true;
				break;
			}
			case REMOTE_CMD_CONNECT_DEVICE:
			{
				stop_loop = true;
				break;
			}
			case REMOTE_CMD_STOP_DISCOVERY:
			{
				stop_loop = true;
				break;
			}
			case REMOTE_CHAR_WRITE:
			{
				stop_loop = true;
				break;
			}
			default:
				printf("Unknown command\n");
				//buffer_reply[0] = ERROR_INVALID_OP;
				break;
			}
			if(stop_loop) break;
		}
	}

	if (read_size == 0) {
		puts("Client disconnected");
		fflush(stdout);
	} else if (read_size == -1) {
		perror("recv failed");
	}

	// Call the corresponding function to process a received command
	switch (op) {
	case REMOTE_CMD_START_DISCOVERY:
	{
		printf("Processing REMOTE_CMD_START_DISCOVERY command\n");
		remote_cmd_start_discovery(adapter);
		break;
	}
	case REMOTE_CMD_CONNECT_DEVICE:
	{
		printf("Processing REMOTE_CMD_CONNECT_DEVICE command\n");
//		bdaddr_t addr;
//		str2ba("F8:1D:78:60:3D:D9", &addr);

		ssize_t len = 1; // because the first byte is the command code

		uint8_t addr_type = buffer_query[1];
		len += 1;

		uint8_t addr_len = buffer_query[2];
		len += 1;

		const uint8_t *addr = &buffer_query[3];
		len += addr_len;

		char *addr_str;
		addr_str = uint8_to_utf8(addr, addr_len, 18);
		printf("Connect a device matching the BT ADDRESS = %s\n", addr_str);

		bdaddr_t addr_bt;
		str2ba(addr_str, &addr_bt);

		device_connect(adapter, addr_bt, addr_type);
		break;
	}
	case REMOTE_CMD_STOP_DISCOVERY:
	{
		printf("Processing REMOTE_CMD_STOP_DISCOVERY command\n");
		remote_cmd_stop_discovery(adapter);
		break;
	}
	case REMOTE_CHAR_WRITE:
	{
		printf("Processing REMOTE_CHAR_WRITE command\n");
		printf("Received packet:\n");
		display_reply_hex(read_size, buffer_query);

		// Let's look inside the packet
		ssize_t len = 1; // start from the first byte (the 0th is a command code)

		uint8_t path_len = buffer_query[len];
		len += 1;

		char* char_path;
		const uint8_t *char_path_raw = &buffer_query[len];
		len += path_len;
		//Transform the binary to string
		char_path = uint8_to_utf8(char_path_raw, path_len, path_len);
		printf("[REMOTE_CHAR_WRITE] characteristic path = %s\n", char_path);

		// Let's get the value and its length
		uint8_t value_len = buffer_query[len];
		len += 1;
		printf("[REMOTE_CHAR_WRITE] check the value length = %d\n", value_len);

		uint8_t *value = &buffer_query[len];//[value_len];
//		memcpy(value, &buffer_query[len], value_len);
		write_characteristic(char_path, value_len, value, adapter);
		break;
	}
	default:
		printf("Unknown command\n");
		break;
	}

	printf("processing finished\n");
}

static int create_socket(struct btd_adapter *adapter)
{
	int c;
	struct sockaddr_in server, client;

	// Create socket
	socket_desc = socket(AF_INET, SOCK_STREAM, 0);

	if (socket_desc == -1) {
		printf("Could not create socket");
		return 1;
	}
	puts("Socket created");

	// Prepare the sockaddr_in structure
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons(6969);

	// Bind
	if (bind(socket_desc, (struct sockaddr *) &server, sizeof(server)) < 0) {
		//print the error message
		perror("bind failed. Error");
		return 1;
	}
	puts("bind done");

	// Listen
	listen(socket_desc, 3);

	// Accept and incoming connection
	puts("Waiting for incoming connections...");
	c = sizeof(struct sockaddr_in);

	// Accept connection from an incoming client
	client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c);
	if (client_sock < 0) {
		perror("accept failed");
		return 1;
	}
	puts("Connection accepted");

	receive_cmd(adapter);

	return 0;
}

static void send_packet(gpointer data,
						gsize data_len)
{
	TRACE_FUNCTION;
	if (g_socket_connection_is_connected(c_connection))
	{
		send_bytes_async(c_connection, data, data_len, NULL);
	} else
	{
		g_print("callback_send : not connected\n");
	}
	return FALSE; // We want to pull a single file.
}

static gboolean callback_read(GIOChannel    * channel,
							  GIOCondition    condition,
							  gpointer        user_data)
{
    TRACE_FUNCTION;
    gsize len;
    GIOStatus ret;
    GSocketConnection * connection = G_SOCKET_CONNECTION(user_data);
    GError            * error = NULL;

    if (condition & G_IO_HUP)
    {
        g_print("The client has disconnected! I feel alone so I stop to listen.\n");
        return FALSE; // The client has disconnected abruptly, remove this GSource
    }

    gchar buffer[BUFSIZ]; // Larger than sizeof(reply_t)
    gsize bytes_read;
    ret = g_io_channel_read_chars(channel, buffer, BUFSIZ, &len, &error);

    switch (ret)
    {
        case G_IO_STATUS_ERROR:
            g_error("Error reading: %s\n", error->message);
            g_object_unref(connection);
            return FALSE;
        case G_IO_STATUS_EOF:
            g_print("EOF\n");
            return FALSE; // The client has closed the connection gracefully, remove this GSource
    }

    if (len)
    {
    	// Parse the received message here
    	uint8_t op = buffer[0];
    	switch (op) {
    	case REMOTE_CMD_START_DISCOVERY:
    	{
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

    		device_connect(default_adapter, addr_bt, addr_type);
    		break;
    	}
    	case REMOTE_CMD_STOP_DISCOVERY:
    	{
    		printf("Processing REMOTE_CMD_STOP_DISCOVERY command\n");
    		remote_cmd_stop_discovery(default_adapter);
    		break;
    	}
    	case REMOTE_CHAR_WRITE:
    	{
    		printf("Processing REMOTE_CHAR_WRITE command\n");
    		printf("Received packet:\n");
    		display_reply_hex(len, buffer);

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
    		write_characteristic(char_path, value_len, value, default_adapter);
    		break;
    	}
    	default:
    		printf("Unknown command\n");
    		break;
    	}
    }

    return TRUE;
}

// This function will get called everytime a client attempts to connect
gboolean callback_connect(
    GSocketService    * service,
    GSocketConnection * connection,
    GObject           * source_object,
    gpointer            user_data
) {
    TRACE_FUNCTION;
    GError * error = NULL;

    c_connection = connection;

    // Print connection
    GSocketAddress *sockaddr = g_socket_connection_get_remote_address(connection, NULL);
    GInetAddress *addr = g_inet_socket_address_get_address(G_INET_SOCKET_ADDRESS(sockaddr));
    guint16 port = g_inet_socket_address_get_port(G_INET_SOCKET_ADDRESS(sockaddr));
    g_print("New Connection from %s:%d\n", g_inet_address_to_string(addr), port);

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

static int my_driver_probe(struct btd_adapter *adapter)
{
	DBG("INSIDE MY DRIVER PROBE!");
	gdbus_config();

	default_adapter = adapter;
	if(sockets)
	{
		int ok = create_socket(adapter);
		if(ok < 0)
		{
			printf("Cant' create socket");
			return 1;
		}
	}

	adapter_device_found_cb_register(device_found);
	adapter_stop_discovery_cb_register(cmd_stop_discovery);
	device_connection_completed_cb_register(send_cache_info);

	if(!sockets)
	{
#if !GLIB_CHECK_VERSION(2, 35, 0)
		g_type_init ();
#endif

		// socket()
		GError * error = NULL;
		service = g_socket_service_new();

		g_socket_listener_add_inet_port((GSocketListener *) service,
										PORT,
										NULL,
										&error);

		if (error)
		{
			g_error(error->message);
			return 1;
		}

		// connect()
    		// Listen to the 'incoming' signal
		g_signal_connect(service,
						 "incoming",
						 G_CALLBACK(callback_connect),
						 NULL);

		// Start the socket service
		g_socket_service_start(service);

		// Run the main loop
		g_print("Listening on localhost:%d\n", PORT);
//		loop = g_main_loop_new(NULL, FALSE);
//		g_main_loop_run(loop);
	}

	return 0;
}

static void my_driver_remove(struct btd_adapter *adapter)
{
	DBG("MY DRIVER REMOVE!");
	g_print("Free\n");
//	g_main_loop_unref(loop);
	g_socket_service_stop(service);
	g_free(service);
}

static struct btd_adapter_driver my_driver = {
	.name = "my-driver",
	.probe = my_driver_probe,
	.remove = my_driver_remove,
};

static int my_plugin_init(void)
{
	DBG("my_plugin_init");

	btd_register_adapter_driver(&my_driver);
}

static void my_plugin_exit(void)
{
	DBG("my_plugin_exit");

//	dbus_message_unref(msg);
//	dbus_message_unref(reply);
//	dbus_connection_close(dbus_connection);
	close(socket_desc);
	//btd_unregister_adapter_driver(&my_driver);
}

BLUETOOTH_PLUGIN_DEFINE(my_plugin, VERSION,
		BLUETOOTH_PLUGIN_PRIORITY_LOW, my_plugin_init, my_plugin_exit)
