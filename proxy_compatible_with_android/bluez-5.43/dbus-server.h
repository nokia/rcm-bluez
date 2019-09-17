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
/*
typedef struct{
	gchar *dev_name;
	gchar *dev_address;
	uint8_t addr_type;
}ConfigEntry;
*/
void rcm_gdbus_run_server();
void rcm_gdbus_stop_server();
void rcm_gdbus_send_signal(char *signal_name, GVariant *signal_data);
/*int rcm_gdbus_find_filter_element( gconstpointer a,
 						 	 	   gconstpointer b);

void rcm_authorize_device(gchar *mac, ConfigEntry *filter_entry);
*/
//int run_dbus_server(DBusConnection *conn); // For using DBus instead of GDBus (was added for some tests, should be suppressed)
#endif /* #ifndef CLIENT_H */

