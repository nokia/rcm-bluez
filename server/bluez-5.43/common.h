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

#define FAIL									0x00
#define SUCCESS									0x01

#define CACHE_LOCATION "/var/lib/bluetooth"
#define PORT 1500
#define TRACE_FUNCTION g_print("## %s ====================\n", __FUNCTION__)

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
    }
    return "Unknown reply code";
}

//HUI
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
