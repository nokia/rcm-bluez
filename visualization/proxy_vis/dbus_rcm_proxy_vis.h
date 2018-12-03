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

#ifndef DBUS_RCM_PROXY_VIS_H
#define DBUS_RCM_PROXY_VIS_H

#include <gtk/gtk.h>
#include <stdbool.h>
#include <stdio.h>
#include <glib/gprintf.h>
#include <gio/gio.h>
#include <gdk-pixbuf/gdk-pixbuf.h>

#include <sys/time.h>


#define PRINT_FUNCTION g_print("## ---------DEBUG-------- %s\n", __FUNCTION__)
//
enum
{
  COL_ADD = 0,
  COL_NAME,
  COL_ADDRESS,
  COL_TYPE_INT,
  COL_TYPE_STR,
  NUM_COLS
} ;

enum
{
	COL_MAC = 0,
	COL_IP,
	NUM_COLS_CONFIGURE
};

enum
{
	COL_LABEL = 0,
	COL_ICON,
	NUM_COL_ICONVIEW
};

struct dbus_data{
	GDBusProxy *proxy; // for gdbus proxy usage, not used for now
	GDBusConnection *conn;
	const gchar     *name_owner;
};

struct signal_data{
	GMainLoop *loop;
	gpointer data; // basically carries a pointer to GtkLabel inside but may be any other element on the window, so I preferred to be generic.
};

struct builders{
	gchar *window_name;
	GtkBuilder *builder;
};

typedef struct active_connection{
	gchar *conn_info;
	gchar *slot_name;
} ActiveConnection;

typedef struct connection_slot_status{
	gchar *image_slot_name;
	gchar *slot_name;
	gchar *label_name;
	gboolean busy;
} ConnectionSlotStatus;

typedef struct device_info{
	gchar *dev_name;
	gchar *dev_addr;
	guint16 addr_type;
	gboolean shown;
} DeviceInfo;

typedef struct icon_view_foreach_data{
	gchar *label;
	gboolean exist;
}IconViewForEachData;

struct dbus_data *get_dbus_info();
void send_dbus_message( gchar *method_name, GVariant *body);
GDBusMessage *send_dbus_request_with_reply(gchar *method_name, GVariant *body);
struct timeval get_time();
struct timeval get_tv_app_start();
void configure_css();

GSList *init_connection_slot_status( GSList	*slots,
											guint	 nslot,
											gchar	*image_name_base,
											gchar	*slot_name_base,
											gchar	*label_name_base);

GSList *get_builder_list();
void print_builder_list(struct builders *builder, gpointer data);
int get_builder_for_window(gconstpointer a, gconstpointer b);
GtkBuilder *append_new_builder(gchar *window_name, gchar *builder_ui_file);
void remove_builder(struct builders* builder);

int proxy_init ( GtkWidget *widget, gpointer data);
const gboolean get_initialization_phase();
void set_initialization_phase(gboolean status);
void add_init_device(GtkBuilder *builder, gchar *dev_name, gchar *dev_addr, guint16 addr_type);

int configure_clients( GtkWidget *widget, gpointer data);

void initialize_main_window();
void free_all_main_window();
void gdbus_unwatch();

// DBus signal callbacks ---------------------------
void rcv_request_signal_callback( GDBusConnection	*conn,
								  const gchar 		*sender_name,
								  const gchar 		*object_path,
								  const gchar 		*interface_name,
								  const gchar 		*signal_name,
								  GVariant 			*parameters,
								  gpointer 			 data);

void send_reply_signal_callback ( GDBusConnection	*conn,
								  const gchar		*sender_name,
								  const gchar		*object_path,
								  const gchar		*interface_name,
								  const gchar		*signal_name,
								  GVariant			*parameters,
								  gpointer			 data);

void device_found_signal_callback( GDBusConnection	*conn,
			     	 	 	 	   const gchar		*sender_name,
								   const gchar		*object_path,
								   const gchar		*interface_name,
								   const gchar		*signal_name,
								   GVariant			*parameters,
								   gpointer			 data);

void new_connection_signal_callback( GDBusConnection	*conn,
									 const gchar		*sender_name,
									 const gchar		*object_path,
									 const gchar		*interface_name,
									 const gchar		*signal_name,
									 GVariant			*parameters,
									 gpointer			 data);

void client_disconnected_signal_callback( GDBusConnection	*conn,
										  const gchar		*sender_name,
										  const gchar		*object_path,
										  const gchar		*interface_name,
										  const gchar		*signal_name,
										  GVariant			*parameters,
										  gpointer			 data);

void device_connected_signal_callback ( GDBusConnection	*conn,
									   	const gchar		*sender_name,
										const gchar 	*object_path,
										const gchar 	*interface_name,
										const gchar 	*signal_name,
										GVariant 		*parameters,
										gpointer 		 data);

void device_disconnected_signal_callback( GDBusConnection	*conn,
										  const gchar		*sender_name,
										  const gchar		*object_path,
										  const gchar		*interface_name,
										  const gchar		*signal_name,
										  GVariant			*parameters,
										  gpointer 			 data);




// ---------------------------

#endif /* #ifndef DBUS_RCM_PROXY_VIS_H */
