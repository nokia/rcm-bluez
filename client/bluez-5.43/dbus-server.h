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
*/

#ifndef RCM_GDBUS_SERVER_H
#define RCM_GDBUS_SERVER_H

#define RCM_OBJECT_PATH			"/org/plugin/RcmObject"
#define RCM_INTERFACE_NAME		"org.plugin.RcmInterface"

typedef void (*conn_info_t)(void *userdata);
static conn_info_t conn_info = NULL;

struct connection {
	gchar *ip_address;
	gchar *port;
};

void rcm_connection_cb_register(conn_info_t cb);
void run_rcm_gdbus_server();
void stop_rcm_gdbus_server();
//void send_rcm_gdbus_signal(char *signal_name, GVariant *signal_data);

#endif /* #ifndef CLIENT_H */
