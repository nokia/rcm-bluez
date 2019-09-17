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

#ifndef COMMON_H
#define COMMON_H
/*
#include <stdint.h>
*/
#include <glib.h>
//#include "gdbus/gdbus.h"

#include <gio/gio.h>

#define REPLY_HEADER_SIZE	1 // in bytes
#define SPECIAL_RQ_SIZE		1 // in bytes
#define CHAR_VALUE_LEN		1 // in bytes

// Remote commands' opcodes
#define REMOTE_CMD_FAIL							0x00
#define REMOTE_CMD_START_DISCOVERY              0x01
#define REMOTE_CMD_CONNECT_DEVICE				0x02
#define REMOTE_CMD_STOP_DISCOVERY				0x03
#define REMOTE_CMD_CACHE_INFO					0x04
#define REMOTE_CMD_RELEASE						0x05
#define REMOTE_CHAR_WRITE						0x06
#define REMOTE_CMD_SET_FILTER                   0X07
#define REMOTE_CMD_DISCONNECT_DEVICE			0x08
#define REMOTE_CMD_GET_MAC						0x09
#define REMOTE_DESC_WRITE						0x0a
#define REMOTE_START_STOP_NOTIF					0x0B

#define FAIL									0x00
#define SUCCESS									0x01

#define CACHE_LOCATION "/var/lib/bluetooth"
#define PORT 1500
#define TRACE_FUNCTION g_print("==================== ## %s ====================\n", __FUNCTION__)

const char *code_to_str(uint8_t code) {
    switch (code) {
        case 0x00: return "REMOTE_CMD_FAIL";
        case 0x01: return "REMOTE_CMD_START_DISCOVERY";
        case 0x02: return "REMOTE_CMD_CONNECT_DEVICE";
        case 0x03: return "REMOTE_CMD_STOP_DISCOVERY";
        case 0x04: return "REMOTE_CMD_CACHE_INFO";
        case 0x05: return "REMOTE_CMD_RELEASE";
        case 0x06: return "REMOTE_CHAR_WRITE";
        case 0x07: return "REMOTE_CMD_SET_FILTER";
        case 0x08: return "REMOTE_CMD_DISCONNECT_DEVICE";
        case 0x09: return "REMOTE_CMD_GET_MAC";
        case 0x0a: return "REMOTE_DESC_WRITE";
        case 0x0B: return "REMOTE_START_STOP_NOTIF";
    }
    return "Unknown reply code";
}

void tohex(char * in, size_t insz, char * out, size_t outsz)
{
    char * pin = in;
    const char * hex = "0123456789abcdef";
    char * pout = out;
    for(; pin < in+insz; pout +=3, pin++){
        pout[0] = hex[(*pin>>4) & 0xF];
        pout[1] = hex[ *pin     & 0xF];
        pout[2] = ':';
        if (pout + 3 - out > outsz){
            /* Better to truncate output string than overflow buffer */
            /* it would be still better to either return a status */
            /* or ensure the target buffer is large enough and it never happen */
            break;
        }
    }
    pout[-1] = 0;
}

char *uint8_to_utf8(const uint8_t *array, uint8_t len, int size)
{
	char utf8_result[size];
	int i;

	printf("uint8 to utf8 \n");

	if (g_utf8_validate((const char *) array, len, NULL))
		return g_strndup((char *) array, len);

	memset(utf8_result, 0, sizeof(utf8_result));
	strncpy(utf8_result, (char *) array, len);

	/* Assume ASCII, and replace all non-ASCII with spaces */
	for (i = 0; utf8_result[i] != '\0'; i++) {
		if (!isascii(utf8_result[i]))
			utf8_result[i] = ' ';
	}

	/* Remove leading and trailing whitespace characters */
	g_strstrip(utf8_result);

	printf("Address after conversion from uint8_t to char* = %s \n", utf8_result);

	return g_strdup(utf8_result);
}

void display_reply_ascii(ssize_t num_recv, uint8_t *server_reply)
{
	printf("Got %zu bytes\n", num_recv);
	ssize_t i;

	// ASCII
	for (i = 0; i < num_recv; ++i) {
		printf("%c", server_reply[i]);
	}
	printf("\n");
}

void display_reply_hex(ssize_t num_recv, uint8_t *server_reply)
{
	printf("Got %zu bytes\n", num_recv);
	ssize_t i;

	// Hex
	for (i = 0; i < num_recv; ++i) {
		printf("%02x ", server_reply[i]);
	}
	printf("\n");
}

bool is_valid_utf8(const char * string)
{
    if (!string)
        return true;

    const unsigned char * bytes = (const unsigned char *)string;
    unsigned int cp;
    int num;

    while (*bytes != 0x00)
    {
        if ((*bytes & 0x80) == 0x00)
        {
            // U+0000 to U+007F
            cp = (*bytes & 0x7F);
            num = 1;
        }
        else if ((*bytes & 0xE0) == 0xC0)
        {
            // U+0080 to U+07FF
            cp = (*bytes & 0x1F);
            num = 2;
        }
        else if ((*bytes & 0xF0) == 0xE0)
        {
            // U+0800 to U+FFFF
            cp = (*bytes & 0x0F);
            num = 3;
        }
        else if ((*bytes & 0xF8) == 0xF0)
        {
            // U+10000 to U+10FFFF
            cp = (*bytes & 0x07);
            num = 4;
        }
        else
            return false;

        bytes += 1;
        for (int i = 1; i < num; ++i)
        {
            if ((*bytes & 0xC0) != 0x80)
                return false;
            cp = (cp << 6) | (*bytes & 0x3F);
            bytes += 1;
        }

        if ((cp > 0x10FFFF) ||
            ((cp >= 0xD800) && (cp <= 0xDFFF)) ||
            ((cp <= 0x007F) && (num != 1)) ||
            ((cp >= 0x0080) && (cp <= 0x07FF) && (num != 2)) ||
            ((cp >= 0x0800) && (cp <= 0xFFFF) && (num != 3)) ||
            ((cp >= 0x10000) && (cp <= 0x1FFFFF) && (num != 4)))
            return false;
    }

    return true;
}

// ++++++++++++++++++++++++++++++++++++++++++++++++++++
// For GMainLoop management


void print_hex(const uint8_t * data, size_t data_len) {
    unsigned i;
    const uint8_t * pc;
    for (i = 0, pc = data; i < data_len; i++, pc++) {
        g_print("%02x%c", *pc, i % 8 == 7 ? '\n' : ' ');
    }
}

gboolean send_bytes(
    GSocketConnection * connection,
    GIOChannel * channel,
    gpointer data,
    gsize data_len
) {
    GError        * error = NULL;
    gsize           len = 0;
    GIOStatus       ret;

    ret = g_io_channel_write_chars(channel, (gchar *) data, data_len, &len, &error);

    switch (ret) {
        case G_IO_STATUS_ERROR:
            g_error("Error writing: %s\n", error->message);
            g_object_unref(connection);
            return FALSE;
        case G_IO_STATUS_NORMAL:
            break;
        case G_IO_STATUS_EOF:
            g_print("send_bytes: G_IO_STATUS_EOF\n");
            break;
        case G_IO_STATUS_AGAIN: // Should not occur
            g_print("send_bytes: G_IO_STATUS_AGAIN\n");
            break;
    }

    if (error) {
        g_print("send_bytes: %s", error->message);
        return FALSE;
    }

    // Send the packet
    ret = g_io_channel_flush(channel, &error);

    if (error) {
        g_print("send_bytes: %s", error->message);
        return FALSE;
    }

    return TRUE;
}
/*
void callback_send_bytes_async(
    GObject      * source_object,
    GAsyncResult * res,
    gpointer       user_data
) {
    TRACE_FUNCTION;
    GError            * error = NULL;
    GSocketConnection * connection = user_data;
    GOutputStream     * ostream;
    gssize num_bytes_written;

    ostream = g_io_stream_get_output_stream(G_IO_STREAM(connection));
    num_bytes_written = g_output_stream_write_bytes_finish(ostream, res, &error);

    if (error) {
        g_error(error->message);
        return;
    }
}

void send_bytes_async(
    GSocketConnection * connection,
    gpointer data,
    gsize data_len,
    GAsyncReadyCallback callback // Pass NULL to use the default callback 'callback_send_bytes_async' (see common.c)
) {
    TRACE_FUNCTION;
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
*/
#endif
// Old functions, may be useful for debugging...

// For kernel sources
//#include "/usr/src/linux-headers-4.9.0-2-common/include/net/bluetooth/hci_core.h"
//#include "/usr/src/linux-headers-4.9.0-2-common/include/net/bluetooth/mgmt.h"
//#include "/usr/src/linux-headers-4.9.0-2-common/include/net/bluetooth/hci.h"
//#include <hci_core.h>
//#include <net/bluetooth/mgmt.h>
//#include <hci.h>

// to comment when adapter_static included
// ------------------------------------------
/*#include "src/shared/mgmt.h"        // mgmt_register
#include "src/adapter.h"            // struct btd_adapter_driver
#include "lib/mgmt.h"               // MGMT_EV_DISCOVERING
#include "src/eir.h"
#include "src/shared/mgmt.h"
#include "src/device.h"
#include "src/log.h"
#include "attrib/gattrib.h"
#include "src/shared/io.h"*/
// ------------------------------------------

//This include contains a copy of adapter.c but with only the static functions
// Before it has been included in remote_bt.c plugin to be able to call static functions
//#include "adapter_static.c"
/*
static void print_iterator(gpointer item, gpointer prefix) {
     printf("%s %s\n", (const char*) prefix, (const char *) item);
}*/
/*
 * static void discovery_started_callback(uint16_t index,
									   uint16_t length,
									   const void *param,
									   void *user_data)
{
	//struct btd_device *dev;
    const struct mgmt_ev_discovering *ev = param;
    struct btd_adapter *adapter = user_data;
    const char *addr_str = "C4:D9:87:C3:30:E3";
    bdaddr_t addr;
    struct eir_data eir_data;
    int len = 0;
    GSList *l;
    int i = 1;
    //uint8_t uuid[4] = {0xE5, 0xFF, 0x00, 0x00};

    // PLOP
    memset(&eir_data, 0, sizeof(eir_data));

    str2ba(addr_str, &addr);
    DBG("NATALYA CALLBACK hci%u type %u discovering %u method %d", adapter->dev_id, ev->type, ev->discovering, adapter->filtered_discovery);

    // Initialize and write name
    g_free(eir_data.name);
    eir_data.name = "Natalya-FAKE-LED";
    //eir_data.services = g_slist_append(eir_data.services, "0000ffe5");
    eir_data.services = g_slist_append(eir_data.services, "0000ffe5-0000-1000-8000-00805f9b34fb");

#ifdef NATALYA
    // 0000ffe5-0000-1000-8000-00805f9b34fb
    uint8_t uuid[16] = {
        0xfb, 0x34, 0x9b, 0x5f,
        0x80, 0x00, 0x00, 0x80,
        0x00, 0x10, 0x00, 0x00,
        0xe5, 0xff, 0x00, 0x00
    };

    // Convert to EIR
    uint8_t data[80];
    data[0] = strlen(eir_data.name) + 1;
    data[1] = EIR_NAME_SHORT;
    memcpy(&data[2], eir_data.name, strlen(eir_data.name) * sizeof(char));
    len = strlen(eir_data.name) + 2;
    //    data[len] = g_slist_length(eir_data.services) * 4 + 1;
    //    data[len + 1] = EIR_UUID32_ALL;
    data[len] = g_slist_length(eir_data.services) * sizeof(uuid) + 1;
    data[len + 1] = EIR_UUID128_ALL;

    for (l = eir_data.services; l != NULL; l = g_slist_next(l)) {
        memcpy(&data[len + 1 + i], uuid, sizeof(uuid));
        i += sizeof(uuid);
    }
    uint16_t eir_len = 80;
#else

    // Convert to EIR
    uint8_t * eir = NULL;
    uint16_t eir_len = 0;
    uint8_t * data = to_eir(&eir_data, eir, &eir_len);
    printf("NATALYA: eir     = %p\n", data);
    printf("NATALYA: eir_len = %zu\n", (size_t) eir_len);
#endif

    // Display
    for (uint8_t i = 0; i < eir_len ; i++) {
        printf("NATALYA CALLBACK DATA [%02d] %02X %c\n", i, data[i], data[i]);
    }
    update_remotely_found_devices(adapter,
            &addr,
            BDADDR_LE_PUBLIC, -55,
            false, true,
            false, data,
            eir_len, NULL);
//    send_event(adapter->mgmt->io->fd, MGMT_EV_DEVICE_FOUND, eir, sizeof(eir));
    DBG("NATALYA CALLBACK3 hci%u type %u discovering %u method %d", adapter->dev_id, ev->type,
            ev->discovering, adapter->filtered_discovery);
}
 * */
