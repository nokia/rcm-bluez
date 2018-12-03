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

#include "dbus_rcm_proxy_vis.h"

static GSList *connections_slot_status = NULL;		// Connections with IP clients (RCM-c)
static GSList *dev_connections_slot_status = NULL;	// Connections with BLE devices
static GSList *active_connections = NULL;			// Active IP clients
static GSList *active_dev_connections = NULL;		// Active BLE peripherals
static guint watcher_id;

GSList *get_connection_slot_status_list()
{
	return connections_slot_status;
}

GSList *get_dev_connections_slot_status_list()
{
	return dev_connections_slot_status;
}

struct timeval compute_time_from_connection(struct timeval *tv_conn, struct timeval *tv_curr)
{
	struct timeval tv_diff;
	timersub(tv_curr, tv_conn, &tv_diff);

	return tv_diff;
}

static void clear_logs(GtkWidget *widget,
        			   gpointer   data)
{
	PRINT_FUNCTION;

	GtkBuilder *builder = data;
	g_printf("clear_logs\n");

	GtkTextView *textview_common_log = (GtkTextView*)gtk_builder_get_object (builder, "textview_common_log");
	GtkTextBuffer *text_buffer_common_log = gtk_text_view_get_buffer(textview_common_log);
	gtk_text_buffer_set_text (text_buffer_common_log, "", -1);

	GtkTextView * textview_client_requests = (GtkTextView*)gtk_builder_get_object (builder, "textview_client_requests");
	GtkTextBuffer *text_buffer_client_requests = gtk_text_view_get_buffer(textview_client_requests);
	gtk_text_buffer_set_text (text_buffer_client_requests, "", -1);

	GtkTextView *textview_proxy_replies = (GtkTextView*)gtk_builder_get_object (builder, "textview_proxy_replies");
	GtkTextBuffer *text_buffer_replies = gtk_text_view_get_buffer(textview_proxy_replies);
	gtk_text_buffer_set_text (text_buffer_replies, "", -1);

	GtkTextView *textview_discovered_peripherals = (GtkTextView*)gtk_builder_get_object (builder, "textview_discovered_peripherals");
	GtkTextBuffer *text_buffer_discovered_peripherals = gtk_text_view_get_buffer(textview_discovered_peripherals);
	gtk_text_buffer_set_text (text_buffer_discovered_peripherals, "", -1);
}

static void textview_insert_and_scroll( GtkTextView *textview,
										gchar *string)
{
	PRINT_FUNCTION;

	if(gtk_text_view_get_editable(textview))
		gtk_text_view_set_editable(textview, FALSE);

	GtkTextBuffer *text_buffer = gtk_text_view_get_buffer(textview);
	GtkTextMark *mark = gtk_text_buffer_get_insert(text_buffer);
	GtkTextIter iter;
	gtk_text_buffer_get_end_iter(text_buffer, &iter);
	gtk_text_buffer_move_mark( text_buffer, mark, &iter );

	gtk_text_buffer_insert_at_cursor (text_buffer, string, strlen(string));
	gtk_text_view_scroll_to_mark(textview, mark, 0.0, TRUE, 0.5, 1 );
}

static void set_common_log_message( GtkBuilder	*builder,
							 gchar		*log_msg)
{
	PRINT_FUNCTION;

	GtkTextView *textview_common_log = (GtkTextView*)gtk_builder_get_object (builder, "textview_common_log");

	if(gtk_text_view_get_editable(textview_common_log))
		gtk_text_view_set_editable(textview_common_log, FALSE);

	GtkTextBuffer *text_buffer_common_log = gtk_text_view_get_buffer(textview_common_log);
	GtkTextMark *mark = gtk_text_buffer_get_insert(text_buffer_common_log);
	GtkTextIter iter;
	gtk_text_buffer_get_end_iter(text_buffer_common_log, &iter);
	gtk_text_buffer_move_mark( text_buffer_common_log, mark, &iter );

	gtk_text_buffer_insert_at_cursor (text_buffer_common_log, log_msg, strlen(log_msg));
	gtk_text_view_scroll_to_mark(textview_common_log, mark, 0.0, TRUE, 0.5, 1 );

}

static int get_slot_by_connection_info( gconstpointer a,
										gconstpointer b)
{
	PRINT_FUNCTION;

	const ActiveConnection *conn = a;
	const gchar *connection_info = b;

	g_printf("in list: %s, new: %s\n", conn->conn_info, connection_info);
	if(strcmp(conn->conn_info, connection_info) == 0)
		return 0;
	return 1;
}

static int get_slot_by_name( gconstpointer a,
							 gconstpointer b)
{
	PRINT_FUNCTION;

	const ConnectionSlotStatus *slot_info = a;
	const gchar *slot_name = b;

	if(strcmp(slot_info->slot_name, slot_name) == 0)
		return 0;
	return 1;
}

static int get_free_slot( gconstpointer a,
						  gconstpointer b)
{
	PRINT_FUNCTION;

	const ConnectionSlotStatus *slot_info = a;
	const gboolean busy = GPOINTER_TO_UINT(b);
	g_printf("[get_free_slot] %s %s %s\n", slot_info->image_slot_name, slot_info->label_name, slot_info->slot_name);
	if(slot_info->busy == busy)
		return 0;
	return 1;
}

void print_slot_info( ConnectionSlotStatus	*slot,
					gpointer				 user_data)
{
	PRINT_FUNCTION;

	printf("List elements connections_slot_status: image = %s, slot = %s, label = %s, busy = %d\n",
						slot->image_slot_name, slot->slot_name, slot->label_name, slot->busy);
}

static void print_active_connections( ActiveConnection *connection,
									  gpointer 			data)
{
	PRINT_FUNCTION;

	g_printf("Active connections: %s in slot: %s\n", connection->conn_info, connection->slot_name);
}

static GSList *set_icon( GtkBuilder	*builder,
					 	 GSList		*active_conn_list,
						 gchar		*icon_file_name,
						 gchar		*image_slot_name,
						 gchar		*image_box_name,
						 gchar		*label_name,
						 gchar		*connection_info)
{
	PRINT_FUNCTION;

	double width, height;

	GtkImage *icon_client = (GtkImage*)gtk_builder_get_object (builder, image_slot_name);
	GtkBox * box_image_client = (GtkBox *)gtk_builder_get_object(builder, image_box_name);
	width = gtk_widget_get_allocated_width ((GtkWidget *)box_image_client);
	height = gtk_widget_get_allocated_height ((GtkWidget *)box_image_client);
	GdkPixbuf *pixbuf = gdk_pixbuf_new_from_file(icon_file_name, NULL); //"./pic/client.png"
	//	new_pix = gdk_pixbuf_scale_simple(pixbuf, 70, 70, GDK_INTERP_BILINEAR);
	GdkPixbuf *new_pix = gdk_pixbuf_scale_simple(pixbuf, width/1.9, height/2, GDK_INTERP_BILINEAR);
	gtk_image_set_from_pixbuf(icon_client, new_pix);

	GtkLabel *lb_client = (GtkLabel*)gtk_builder_get_object (builder, label_name);
	gtk_label_set_text(lb_client, connection_info);

	ActiveConnection *conn = g_malloc(sizeof(ActiveConnection));
	conn->conn_info = connection_info;
	conn->slot_name = image_box_name;
	active_conn_list = g_slist_append(active_conn_list, conn);
	g_slist_foreach(active_conn_list, (GFunc)print_active_connections, NULL);

	return active_conn_list;
}

static void remove_icon( GtkBuilder	*builder,
						 gchar		*image_slot_name,
						 gchar		*label_name)
{
	PRINT_FUNCTION;

	GtkImage *icon_client = (GtkImage*)gtk_builder_get_object (builder, image_slot_name);
	GtkLabel *lb_client = (GtkLabel*)gtk_builder_get_object (builder, label_name);
	gtk_image_clear (icon_client);
	gtk_label_set_text(lb_client, "");
}

GSList *init_connection_slot_status( GSList	*slots,
											guint	 nslot,
											gchar	*image_name_base,
											gchar	*slot_name_base,
											gchar	*label_name_base)
{
	PRINT_FUNCTION;

	for(int i=0; i<3; i++)
	{
		/*
		int n = i;
		int count = 0;
		while(n != 0)
		{
			n = n/10;
			++count;
		}
		int slot_name_length = strlen(slot_name_base) + count;
		int label_name_length = strlen(label_name_base) + count;
		int image_name_length = strlen(image_name_base) + count;
		 */
		gchar *slot_name = g_malloc(sizeof(gchar) * 20);
		gchar *label_name = g_malloc(sizeof(gchar) * 20);
		gchar *image_slot = g_malloc(sizeof(gchar) * 20);

		sprintf(slot_name, "%s%d", slot_name_base, i);
		sprintf(label_name, "%s%d", label_name_base, i);
		sprintf(image_slot, "%s%d", image_name_base, i);

		ConnectionSlotStatus *slot = malloc(sizeof(ConnectionSlotStatus));

		slot->image_slot_name = image_slot;
		slot->slot_name = slot_name;
		slot->label_name = label_name;
		slot->busy = FALSE;

		slots = g_slist_append(slots, slot);
	}

	return slots;
//	g_slist_foreach(connections_slot_status, (GFunc)print_slot_info, NULL);
}

void rcv_request_signal_callback( GDBusConnection	*conn,
								  const gchar 		*sender_name,
								  const gchar 		*object_path,
								  const gchar 		*interface_name,
								  const gchar 		*signal_name,
								  GVariant 			*parameters,
								  gpointer 			 data)
{
	PRINT_FUNCTION;

	GtkBuilder *builder = data;
	gchar *request_type;
	gchar *source;
	gchar *string;
	struct timeval curr_time;
	struct timeval time;

	curr_time = get_time();
	struct timeval tv_app_start = get_tv_app_start();
	time = compute_time_from_connection(&tv_app_start, &curr_time);

	g_variant_get (parameters, "(ss)", &request_type, &source);
	string = g_strdup_printf ("%s from: %s\n", request_type, source);

	GtkTextView * textview_client_requests = (GtkTextView*)gtk_builder_get_object (builder, "textview_client_requests");

	textview_insert_and_scroll(textview_client_requests, string);

	gchar *log_msg = g_strdup_printf ("%ld.%06ld s\t%s\t%s\tRcvRequest\n", time.tv_sec, time.tv_usec, request_type, source);
	set_common_log_message(builder, log_msg);

	g_free (string);
	g_free (log_msg);
}

void device_found_signal_callback( GDBusConnection	*conn,
			     	 	 	 	   const gchar		*sender_name,
								   const gchar		*object_path,
								   const gchar		*interface_name,
								   const gchar		*signal_name,
								   GVariant			*parameters,
								   gpointer			 data)
{
	PRINT_FUNCTION;

	GtkBuilder *builder = data;
	gchar *device_address;
	gchar *device_name;
	gboolean filter_passed;
	guint16 addr_type;

	if(get_initialization_phase())
	{
		g_variant_get (parameters, "(ssqb)", &device_name, &device_address, &addr_type, &filter_passed);
		//TODO: Add an element to gtk_list_box (Do it only if window open ?)
		// Should be ok because we check whether a corresponding builder exists
		GSList *builder_list = get_builder_list();
		GSList *builder_list_el = g_slist_find_custom(builder_list, "proxy_init_window", get_builder_for_window);
		if(builder_list_el == NULL) return; // If proxy_init_window's builder doesn't exist, ignore

		struct builders *builders = builder_list_el->data;
		add_init_device(builders->builder, device_name, device_address, addr_type);
	}
	else
	{
		struct timeval curr_time;
		struct timeval time;
		gchar *string;

		curr_time = get_time();
		struct timeval tv_app_start = get_tv_app_start();
		time = compute_time_from_connection(&tv_app_start, &curr_time);

/*
 * As defined in /usr/local/include/bluetooth.h:
 * #define BDADDR_BREDR           0x00
 * #define BDADDR_LE_PUBLIC       0x01
 * #define BDADDR_LE_RANDOM       0x02
*/
		g_variant_get (parameters, "(ssqb)", &device_name, &device_address, &addr_type, &filter_passed);
		gchar *filter = g_strdup_printf(filter_passed?"FP":""); // FP as "filter passed"
		gchar *addr_type_str = g_strdup_printf(addr_type==0?"BDADDR_BREDR":addr_type==1?"BDADDR_LE_PUBLIC":addr_type==2?"BDADDR_LE_RANDOM":"UNKNOWN");

		string = g_strdup_printf ("%ld.%06ld s\t%s\t%s\t%s\t%s\n", time.tv_sec, time.tv_usec, device_name, device_address, addr_type_str, filter);

		GtkTextView *textview_discovered_peripherals = (GtkTextView*)gtk_builder_get_object (builder, "textview_discovered_peripherals");

		textview_insert_and_scroll(textview_discovered_peripherals, string);

		gchar *log_msg;
		log_msg = g_strdup_printf ("%ld.%06ld s\t%s\t%s\t\%s\t%s\tDeviceFound\n", time.tv_sec, time.tv_usec, device_name, device_address, addr_type_str, filter);
		set_common_log_message(builder, log_msg);

		g_free (string);
		g_free (filter);
		g_free (log_msg);
	}
}

void init_active_connections(GtkBuilder *builder)
{
	PRINT_FUNCTION;

	GDBusMessage *active_clients_reply = send_dbus_request_with_reply("GetActiveClients", NULL);
	if(active_clients_reply != NULL)
	{
		GVariantIter *iter;
		gchar *str;
		GVariant *reply_body = g_dbus_message_get_body(active_clients_reply);
		g_variant_get (reply_body, "(as)", &iter);

		while (g_variant_iter_loop (iter, "s", &str))
		{
			g_printf("[fill_active_clients_treeview] = %s\n", str);
			const char delimiters[] = ",";
			gchar *str_copy;
			gchar *token;

			str_copy = g_strdup_printf("%s", str);

			token = strsep(&str_copy, delimiters);
			gchar *mac = g_malloc(sizeof(gchar) * strlen(token));
			sprintf(mac, "%s", token);

			token = strsep(&str_copy, delimiters);
			gchar *ip = g_malloc(sizeof(gchar) * strlen(token));
			sprintf(ip, "%s", token);
//
			gchar *new_connection_info;
			struct timeval curr_time;
			struct timeval time;

			curr_time = get_time();
			struct timeval tv_app_start = get_tv_app_start();
			time = compute_time_from_connection(&tv_app_start, &curr_time);

			GtkTextView *textview_actives_connections = (GtkTextView*)gtk_builder_get_object (builder, "textview_actives_connections");
			new_connection_info = g_strdup_printf("%ld.%06ld s\tIP: %s MAC: %s\t connected\n", time.tv_sec, time.tv_usec, ip, mac);

			textview_insert_and_scroll(textview_actives_connections, new_connection_info);

			GSList *conn_info = g_slist_find_custom(active_connections, ip, get_slot_by_connection_info);
			if(conn_info != NULL) return; // If client is already connected and picture is set, just ignore

			gboolean busy = FALSE;

			GSList *free_slot = g_slist_find_custom(connections_slot_status, GINT_TO_POINTER(busy), get_free_slot);
			if(!free_slot) return;

			ConnectionSlotStatus *slot = free_slot->data;
			active_connections = set_icon(builder, active_connections, "./pic/client.png", slot->image_slot_name, slot->slot_name, slot->label_name, g_strdup(ip));
			slot->busy = TRUE;
//
			g_free(mac);
			g_free(ip);
			g_free(new_connection_info);
			g_free(str_copy);
		}
	}
}

void new_connection_signal_callback( GDBusConnection	*conn,
									 const gchar		*sender_name,
									 const gchar		*object_path,
									 const gchar		*interface_name,
									 const gchar		*signal_name,
									 GVariant			*parameters,
									 gpointer			 data)
{
	PRINT_FUNCTION;

	GtkBuilder *builder = data;
	gchar *addr;
	gchar *mac;
	gchar *new_connection_info;
	struct timeval curr_time;
	struct timeval time;

	curr_time = get_time();
	struct timeval tv_app_start = get_tv_app_start();
	time = compute_time_from_connection(&tv_app_start, &curr_time);

	g_variant_get (parameters, "(ss)", &addr, &mac);

	GtkTextView *textview_actives_connections = (GtkTextView*)gtk_builder_get_object (builder, "textview_actives_connections");
	new_connection_info = g_strdup_printf("%ld.%06ld s\tIP: %s MAC: %s\t connected\n", time.tv_sec, time.tv_usec, addr, mac);

	textview_insert_and_scroll(textview_actives_connections, new_connection_info);

	GSList *conn_info = g_slist_find_custom(active_connections, addr, get_slot_by_connection_info);
	if(conn_info != NULL) return; // If client is already connected and picture is set, just ignore

	gboolean busy = FALSE;

	GSList *free_slot = g_slist_find_custom(connections_slot_status, GINT_TO_POINTER(busy), get_free_slot);
	if(!free_slot) return;

	ConnectionSlotStatus *slot = free_slot->data;
	active_connections = set_icon(builder, active_connections, "./pic/client.png", slot->image_slot_name, slot->slot_name, slot->label_name, addr);
	slot->busy = TRUE;

	g_free(new_connection_info);

//	g_slist_foreach(connections_slot_status, (GFunc)print_slot_info, NULL);
}

void device_disconnected_signal_callback( GDBusConnection	*conn,
										  const gchar		*sender_name,
										  const gchar		*object_path,
										  const gchar		*interface_name,
										  const gchar		*signal_name,
										  GVariant			*parameters,
										  gpointer 			 data)
{
	PRINT_FUNCTION;

	g_printf("Got signal %s\n", signal_name);
	GtkBuilder *builder = data;
	gchar *dev_addr;

	g_variant_get (parameters, "(s)", &dev_addr);

	g_printf("Print before searching\n");
	g_slist_foreach(active_dev_connections, (GFunc)print_active_connections, NULL);
	g_slist_foreach(dev_connections_slot_status, (GFunc)print_slot_info, NULL);
	g_printf("----------------------\n");

	GSList *conn_info = g_slist_find_custom(active_dev_connections, dev_addr, get_slot_by_connection_info);
	if(!conn_info) return;

	ActiveConnection *active_conn = conn_info->data;
	GSList *slot = g_slist_find_custom(dev_connections_slot_status, active_conn->slot_name, get_slot_by_name);
	if(!slot) return;

	ConnectionSlotStatus *dev_slot = slot->data;

	remove_icon(builder, dev_slot->image_slot_name, dev_slot->label_name);
	dev_slot->busy = FALSE;
	active_dev_connections = g_slist_remove (active_dev_connections, active_conn);

	g_printf("Print after searching\n");
	g_slist_foreach(active_dev_connections, (GFunc)print_active_connections, NULL);
	g_slist_foreach(dev_connections_slot_status, (GFunc)print_slot_info, NULL);
	g_printf("----------------------\n");

}

void client_disconnected_signal_callback( GDBusConnection	*conn,
										  const gchar		*sender_name,
										  const gchar		*object_path,
										  const gchar		*interface_name,
										  const gchar		*signal_name,
										  GVariant			*parameters,
										  gpointer			 data)
{
	PRINT_FUNCTION;

	g_printf("Got signal %s\n", signal_name);
	GtkBuilder *builder = data;
	gchar *addr;
	guint16 port;
	gchar *new_connection_info;
	struct timeval curr_time;
	struct timeval time;

	curr_time = get_time();
	struct timeval tv_app_start = get_tv_app_start();
	time = compute_time_from_connection(&tv_app_start, &curr_time);

	g_variant_get (parameters, "(sq)", &addr, &port);

	GtkTextView *textview_actives_connections = (GtkTextView*)gtk_builder_get_object (builder, "textview_actives_connections");
	new_connection_info = g_strdup_printf("%ld.%06ld s\t%s:%d\t disconnected\n", time.tv_sec, time.tv_usec, addr, port);

	textview_insert_and_scroll(textview_actives_connections, new_connection_info);

	g_printf("Print before searching\n");
	g_slist_foreach(active_connections, (GFunc)print_active_connections, NULL);
	g_slist_foreach(connections_slot_status, (GFunc)print_slot_info, NULL);
	g_printf("----------------------\n");

	GSList *conn_info = g_slist_find_custom(active_connections, addr, get_slot_by_connection_info);
	if(!conn_info) return;

	ActiveConnection *active_conn = conn_info->data;
	GSList *slot = g_slist_find_custom(connections_slot_status, active_conn->slot_name, get_slot_by_name);
	if(!slot) return;

	ConnectionSlotStatus *client_slot = slot->data;

	remove_icon(builder, client_slot->image_slot_name, client_slot->label_name);
	client_slot->busy = FALSE;
	active_connections = g_slist_remove (active_connections, active_conn);

	g_printf("Print after searching\n");
	g_slist_foreach(active_connections, (GFunc)print_active_connections, NULL);
	g_slist_foreach(connections_slot_status, (GFunc)print_slot_info, NULL);
	g_printf("----------------------\n");
}

void device_connected_signal_callback ( GDBusConnection	*conn,
									   	const gchar		*sender_name,
										const gchar 	*object_path,
										const gchar 	*interface_name,
										const gchar 	*signal_name,
										GVariant 		*parameters,
										gpointer 		 data)
{
	PRINT_FUNCTION;

	GtkBuilder *builder = data;
	gchar *dev_addr;
	g_variant_get (parameters, "(s)", &dev_addr);

	GSList *conn_info = g_slist_find_custom(active_dev_connections, dev_addr, get_slot_by_connection_info);
	if(conn_info != NULL) return; // If device is already connected and picture is set, just ignore

	gboolean busy = FALSE;

	GSList *free_slot = g_slist_find_custom(dev_connections_slot_status, GINT_TO_POINTER(busy), get_free_slot);
	if(!free_slot) return;

	ConnectionSlotStatus *slot = free_slot->data;
	active_dev_connections = set_icon(builder, active_dev_connections, "./pic/bulb.png", slot->image_slot_name, slot->slot_name, slot->label_name, dev_addr);
	slot->busy = TRUE;
}

void send_reply_signal_callback ( GDBusConnection	*conn,
								  const gchar		*sender_name,
								  const gchar		*object_path,
								  const gchar		*interface_name,
								  const gchar		*signal_name,
								  GVariant			*parameters,
								  gpointer			 data)
{
	PRINT_FUNCTION;

	GtkBuilder *builder = data;
	gchar *reply_type;
	gchar *destination;
	gchar *string;
	struct timeval curr_time;
	struct timeval time;

	curr_time = get_time();
	struct timeval tv_app_start = get_tv_app_start();
	time = compute_time_from_connection(&tv_app_start, &curr_time);

	g_variant_get (parameters, "(ss)", &reply_type, &destination);
	string = g_strdup_printf ("%s to: %s\n", reply_type, destination);

	GtkTextView *textview_proxy_replies = (GtkTextView*)gtk_builder_get_object (builder, "textview_proxy_replies");

	textview_insert_and_scroll(textview_proxy_replies, string);

	gchar *log_msg = g_strdup_printf ("%ld.%06ld s\t%s\t%s\tSndReply\n", time.tv_sec, time.tv_usec, reply_type, destination);
	set_common_log_message(builder, log_msg);

	g_free (string);
}

static void free_connection_list_elements( gpointer data)
{
	PRINT_FUNCTION;

	ConnectionSlotStatus *element = data;
	g_free(element->image_slot_name);
	g_free(element->label_name);
	g_free(element->slot_name);
	g_free(element);
}

static void free_active_connections_elements( gpointer data)
{
	PRINT_FUNCTION;

	ActiveConnection *element = data;
	g_free(element->conn_info);
	g_free(element->slot_name);
	g_free(element);
}

void free_all_main_window()
{
	g_slist_free_full(connections_slot_status, free_connection_list_elements);
	g_slist_free_full(dev_connections_slot_status, free_connection_list_elements);

	g_slist_free_full(active_connections, free_active_connections_elements);
	g_slist_free_full(active_dev_connections, free_active_connections_elements);
}


static void on_name_appeared( GDBusConnection	*connection,
                  	  	  	  const gchar		*name,
							  const gchar		*name_owner,
							  gpointer			 user_data)
{
	PRINT_FUNCTION;

	struct dbus_data *dbus_info = get_dbus_info();

	dbus_info->name_owner = name_owner;
	dbus_info->conn = connection;
	GtkBuilder *builder = user_data;
	init_active_connections(builder);

	g_dbus_connection_signal_subscribe(dbus_info->conn,
									   "org.plugin.RcmServer",
									   "org.plugin.RcmInterface",
									   "RcvRequest",
									   "/org/plugin/RcmObject",
									   NULL, /* arg0 */
									   G_DBUS_SIGNAL_FLAGS_NONE,
									   rcv_request_signal_callback,
									   builder, /* user data */
									   NULL);

	g_dbus_connection_signal_subscribe(dbus_info->conn,
									   "org.plugin.RcmServer",
									   "org.plugin.RcmInterface",
									   "SendReply",
									   "/org/plugin/RcmObject",
									   NULL, /* arg0 */
									   G_DBUS_SIGNAL_FLAGS_NONE,
									   send_reply_signal_callback,
									   builder, /* user data */
									   NULL);

	g_dbus_connection_signal_subscribe(dbus_info->conn,
									   "org.plugin.RcmServer",
									   "org.plugin.RcmInterface",
									   "DeviceFound",
									   "/org/plugin/RcmObject",
									   NULL, /* arg0 */
									   G_DBUS_SIGNAL_FLAGS_NONE,
									   device_found_signal_callback,
									   builder, /* user data */
									   NULL);

	g_dbus_connection_signal_subscribe(dbus_info->conn,
									   "org.plugin.RcmServer",
									   "org.plugin.RcmInterface",
									   "NewConnection",
									   "/org/plugin/RcmObject",
									   NULL, /* arg0 */
									   G_DBUS_SIGNAL_FLAGS_NONE,
									   new_connection_signal_callback,
									   builder, /* user data */
									   NULL);

	g_dbus_connection_signal_subscribe(dbus_info->conn,
									   "org.plugin.RcmServer",
									   "org.plugin.RcmInterface",
									   "ClientDisconnected",
									   "/org/plugin/RcmObject",
									   NULL, /* arg0 */
									   G_DBUS_SIGNAL_FLAGS_NONE,
									   client_disconnected_signal_callback,
									   builder, /* user data */
									   NULL);

	g_dbus_connection_signal_subscribe(dbus_info->conn,
									   "org.plugin.RcmServer",
									   "org.plugin.RcmInterface",
									   "DeviceConnected",
									   "/org/plugin/RcmObject",
									   NULL, /* arg0 */
									   G_DBUS_SIGNAL_FLAGS_NONE,
									   device_connected_signal_callback,
									   builder, /* user data */
									   NULL);

	g_dbus_connection_signal_subscribe(dbus_info->conn,
									   "org.plugin.RcmServer",
									   "org.plugin.RcmInterface",
									   "DeviceDisconnected",
									   "/org/plugin/RcmObject",
									   NULL, /* arg0 */
									   G_DBUS_SIGNAL_FLAGS_NONE,
									   device_disconnected_signal_callback,
									   builder, /* user data */
									   NULL);
}

static void on_name_vanished ( GDBusConnection	*connection,
							   const gchar     	*name,
							   gpointer          user_data)
{
	PRINT_FUNCTION;

	g_printerr ("Failed to get name owner for %s\n"
	      "Is GDbus server running?\n",
	      name);
	exit (1);
}

void gdbus_unwatch()
{
	g_bus_unwatch_name (watcher_id);
}

static void install_gtk_signal_handlers()
{
	PRINT_FUNCTION;

	GObject *window;
	GObject *clear_button;
	GObject *quit_button;
	double width, height;

	GSList *builder_list = get_builder_list();
	GSList *builder_list_el = g_slist_find_custom(builder_list, "main_window", get_builder_for_window);
	if(builder_list_el == NULL)
	{
		g_printf("Builder not found\n");
		return;
	}

	struct builders *builders = builder_list_el->data;

	window = gtk_builder_get_object (builders->builder, "main_window");
	gtk_widget_set_app_paintable ((GtkWidget *)window, TRUE);
	gtk_window_set_decorated((GtkWindow*)window, TRUE);
	g_signal_connect (window, "destroy", G_CALLBACK (gtk_main_quit), NULL);

	GtkImage *image_proxy = (GtkImage*)gtk_builder_get_object (builders->builder, "proxy_pic");
	GtkBox * box_image_proxy = (GtkBox *)gtk_builder_get_object(builders->builder, "box_image_proxy");
	width = gtk_widget_get_allocated_width ((GtkWidget *)box_image_proxy);
	height = gtk_widget_get_allocated_height ((GtkWidget *)box_image_proxy);
	GdkPixbuf *pixbuf = gdk_pixbuf_new_from_file("./pic/proxy.png", NULL);
	GdkPixbuf *new_pix = gdk_pixbuf_scale_simple(pixbuf, width, height/1.5, GDK_INTERP_BILINEAR);
	gtk_image_set_from_pixbuf(image_proxy, new_pix);

	GtkImage *image_nbl_logo = (GtkImage*)gtk_builder_get_object (builders->builder, "image_nbl_logo");
	pixbuf = gdk_pixbuf_new_from_file("./pic/logo_white.png", NULL);
	width = gtk_widget_get_allocated_width ((GtkWidget *)image_nbl_logo);
	height = gtk_widget_get_allocated_height ((GtkWidget *)image_nbl_logo);
	new_pix = gdk_pixbuf_scale_simple(pixbuf, width/1.3, height, GDK_INTERP_BILINEAR);
	gtk_image_set_from_pixbuf(image_nbl_logo, new_pix);

	GtkTextView * textview_client_requests = (GtkTextView *)gtk_builder_get_object (builders->builder, "textview_client_requests");
	gtk_text_view_set_wrap_mode(textview_client_requests, GTK_WRAP_CHAR);

	clear_button = gtk_builder_get_object (builders->builder, "clear_button");
	g_signal_connect (clear_button, "clicked", G_CALLBACK (clear_logs), builders->builder);

	quit_button = gtk_builder_get_object (builders->builder, "quit");
	g_signal_connect (quit_button, "clicked", G_CALLBACK (gtk_main_quit), NULL);

	GObject *button_initialize;
	button_initialize = gtk_builder_get_object (builders->builder, "button_initialize");
	g_signal_connect (button_initialize, "clicked", G_CALLBACK (proxy_init), window);

	GObject *button_configure_clients;
	button_configure_clients = gtk_builder_get_object(builders->builder, "button_configure_clients");
	g_signal_connect (button_configure_clients, "clicked", G_CALLBACK(configure_clients), window);
}

static void main_window_init_slots()
{
	PRINT_FUNCTION;

	connections_slot_status = init_connection_slot_status(connections_slot_status, 3, "icon_client", "box_image_client", "lb_client");
	dev_connections_slot_status = init_connection_slot_status(dev_connections_slot_status, 3, "icon_peripheral", "box_image_peripheral", "lb_device");
}

void initialize_main_window()
{
	PRINT_FUNCTION;

	GtkBuilder *builder = append_new_builder("main_window", "builder_rcm_proxy.ui");

	// Dbus watcher
	watcher_id = g_bus_watch_name (G_BUS_TYPE_SYSTEM,
								   "org.plugin.RcmServer",
								   G_BUS_NAME_WATCHER_FLAGS_NONE,
								   on_name_appeared,
								   on_name_vanished,
								   builder,
								   NULL);

	configure_css();
	install_gtk_signal_handlers();
	main_window_init_slots();
}
