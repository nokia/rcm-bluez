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

//#include <gio/gio.h>
//#include <gdk-pixbuf/gdk-pixbuf.h>
//#include "client_filter_window.h"

#include "dbus_rcm_proxy_vis.h"

typedef struct selected_client{
	gchar *mac;
	gchar *ip;
}SelectedClient;

SelectedClient selected_client_info;

GDBusMessage *send_dbus_request_with_reply(gchar *method_name, GVariant *body)
{
	PRINT_FUNCTION;

	GError       **error = NULL;
	GDBusMessage *method_call_message;
	GDBusMessage *method_reply_message;

	method_call_message = NULL;
	method_reply_message = NULL;

	struct dbus_data *dbus_info = get_dbus_info();

	method_call_message = g_dbus_message_new_method_call ( dbus_info->name_owner,
														   "/org/plugin/RcmObject",
														   "org.plugin.RcmInterface",
														   method_name);
	if(body != NULL)
	{
		g_printf("body = %p\n", body);
		g_dbus_message_set_body(method_call_message, body);
	}

	method_reply_message = g_dbus_connection_send_message_with_reply_sync ( dbus_info->conn,
																			method_call_message,
																			G_DBUS_SEND_MESSAGE_FLAGS_NONE,
																			-1,
																			NULL, /* out_serial */
																			NULL, /* cancellable */
																			error);
	if (method_reply_message == NULL)
		goto out;

	return method_reply_message;

	out:
		g_object_unref (method_call_message);
		g_object_unref (method_reply_message);

		return NULL;
}

void init_client_filter_iconview(GtkBuilder *builder, GDBusMessage *client_filter)
{
	PRINT_FUNCTION;

	GVariantIter *iter_init_f;
	gchar *str_init_f;
	GtkTreeIter   tree_iter;
	GVariant *reply_body_init_f = g_dbus_message_get_body(client_filter);
	g_variant_get (reply_body_init_f, "(as)", &iter_init_f);

	GObject *icon_view_filter = gtk_builder_get_object (builder, "icon_view_filter");
	GtkTreeModel *icon_view_model = gtk_icon_view_get_model((GtkIconView *)icon_view_filter);
	gtk_list_store_clear(GTK_LIST_STORE(icon_view_model));

	while (g_variant_iter_loop (iter_init_f, "s", &str_init_f))
	{
		if(strcmp(str_init_f, "empty") == 0)
			return;

		gchar *str_copy;
		GdkPixbuf    *pix;

		str_copy = g_strdup_printf("%s", str_init_f);

		pix = gdk_pixbuf_new_from_file("./pic/bt_logo.png", NULL); //"./pic/client.png"
		GdkPixbuf *new_pix = gdk_pixbuf_scale_simple(pix, 50, 50, GDK_INTERP_BILINEAR);
		gtk_list_store_append(GTK_LIST_STORE(icon_view_model), &tree_iter);
		gtk_list_store_set(GTK_LIST_STORE(icon_view_model), &tree_iter, COL_LABEL, str_copy, COL_ICON, new_pix, -1);
		g_object_unref(G_OBJECT(pix));
		g_object_unref(G_OBJECT(new_pix));

		g_free(str_copy);
	}
}

void client_treeview_row_activated( GtkTreeView       *tree_view,
					   	   	   	    GtkTreePath       *path,
									GtkTreeViewColumn *column,
									gpointer           user_data)
{
	PRINT_FUNCTION;

//	GtkWindow *client_filter_win = user_data;
	GtkBuilder *builder = user_data;
    GtkTreeIter iter;

	GtkTreeModel *treeview_model = gtk_tree_view_get_model((GtkTreeView *)tree_view);
    gtk_tree_model_get_iter_from_string (treeview_model, &iter, gtk_tree_path_to_string(path));
    gchar *mac;
    gchar *ip;
	gtk_tree_model_get(treeview_model, &iter, COL_MAC, &mac, COL_IP, &ip, -1);
	g_printf("mac = %s\n", mac);
	selected_client_info.mac = mac;
	selected_client_info.ip = ip;

	GVariant *client_info = g_variant_new ("(s)", mac);
	GDBusMessage *client_filter = send_dbus_request_with_reply("GetClientFilter", client_info);

	if(client_filter != NULL)
		init_client_filter_iconview(builder, client_filter);
	// implement "GetClientFilter and fill the right iconview"

}

gboolean check_presence ( GtkTreeModel	*model,
					     GtkTreePath 	*path,
						 GtkTreeIter 	*iter,
						 gpointer 		 user_data)
{
	PRINT_FUNCTION;

	IconViewForEachData *data = user_data;

	gchar *label_dst;
	gtk_tree_model_get(model, iter, COL_LABEL, &label_dst, -1);

	if(strcmp(data->label, label_dst) == 0)
	{
		data->exist = TRUE;
		return TRUE;
	}
	return FALSE;
}

static void cb_drag_data_get( GtkWidget			*widget,
							  GdkDragContext	*context,
							  GtkSelectionData	*selection_data,
							  guint				 target_type,
							  guint				 time,
							  gpointer			 user_data)
{
	gtk_selection_data_set
	(
			selection_data,         /* Allocated GdkSelectionData object */
			gtk_selection_data_get_target(selection_data), /* target type */
			32,                 /* number of bits per 'unit' */
			(guchar*) &widget,/* pointer to data to be sent */
			sizeof (gpointer)   /* length of data in units */
	);
}

static void cb_drag_data_received( GtkWidget		*widget,
								   GdkDragContext	*context,
								   gint				 x,
								   gint				 y,
								   GtkSelectionData *selection_data,
								   guint			 target_type,
								   guint			 time,
								   gpointer			 data)
{
	//
	GtkWidget * handler = *(gpointer*)gtk_selection_data_get_data(selection_data);


	GList *selected_items = gtk_icon_view_get_selected_items((GtkIconView *)handler);
	GList *item = g_list_first (selected_items);
	GtkTreePath *path = item->data;
	GtkTreeModel *icon_view_model = gtk_icon_view_get_model((GtkIconView *)handler);
	GtkTreeIter iter;
	gtk_tree_model_get_iter(icon_view_model, &iter, path);

	gchar *label;
	GdkPixbuf *pix;

	gtk_tree_model_get(icon_view_model, &iter, COL_LABEL, &label, COL_ICON, &pix, -1);

	GtkTreeIter tree_iter;
	GtkTreeModel *dest_icon_view_model = gtk_icon_view_get_model((GtkIconView *)widget);

	IconViewForEachData filter_data;
	filter_data.label = label;
	filter_data.exist = FALSE;
	gtk_tree_model_foreach(dest_icon_view_model, check_presence, &filter_data);

	if(filter_data.exist) return;

	gtk_list_store_append(GTK_LIST_STORE(dest_icon_view_model), &tree_iter);
	gtk_list_store_set(GTK_LIST_STORE(dest_icon_view_model), &tree_iter, COL_LABEL, label, COL_ICON, pix, -1);
	g_object_unref(G_OBJECT(pix));

}

static gboolean cb_drag_drop( GtkWidget        *widget,
							  GdkDragContext   *context,
							  gint              x,
							  gint              y,
							  GtkSelectionData *data,
							  guint             info,
							  guint             time,
							  gpointer          user_data)
{
//	const gchar *name = gtk_widget_get_name (widget);
//	g_print ("%s: drag_data_received_handl data = %p lengt = %d\n", name, data, gtk_selection_data_get_length(data));

    GdkAtom         target_type;
    gboolean        is_valid_drop_site;

    is_valid_drop_site = TRUE;

    if (gdk_drag_context_list_targets (context))
    {
    	target_type = GDK_POINTER_TO_ATOM(g_list_nth_data (gdk_drag_context_list_targets(context), 0));
    	gtk_drag_get_data(widget, context, target_type, time);
    }
    else
    {
    	is_valid_drop_site = FALSE;
    }

    return is_valid_drop_site;

	/*
	if((data != NULL) && (gtk_selection_data_get_length(data) >= 0))
	{
		g_printf("[cb_drag_drop] Data received\n");

		GdkDragAction action;

		// handle data here

		action = gdk_drag_context_get_selected_action (context);
		if (action == GDK_ACTION_ASK)
		{
			GtkWidget *dialog;
			gint response;

			dialog = gtk_message_dialog_new (NULL,
					GTK_DIALOG_MODAL |
					GTK_DIALOG_DESTROY_WITH_PARENT,
					GTK_MESSAGE_INFO,
					GTK_BUTTONS_YES_NO,
					"Move the data ?\n");
			response = gtk_dialog_run (GTK_DIALOG (dialog));
			gtk_widget_destroy (dialog);

			if (response == GTK_RESPONSE_YES)
				action = GDK_ACTION_MOVE;
			else
				action = GDK_ACTION_COPY;
		}

		gtk_drag_finish (context, TRUE, action == GDK_ACTION_MOVE, time);
	}
	else
		gtk_drag_finish (context, FALSE, FALSE, time);
*/
}

void fill_active_clients_treeview( GtkBuilder *builder_configure_clients,
								   GDBusMessage *get_active_clients_reply)
{
	// -----------------------------------------------------------------------------------------------------
	// Prepare clients_treeview for filing with active clients
	// -----------------------------------------------------------------------------------------------------

	GObject *clients_treeview = gtk_builder_get_object (builder_configure_clients, "clients_treeview");
	g_signal_connect(clients_treeview, "row-activated", G_CALLBACK(client_treeview_row_activated), builder_configure_clients);

	// -----------------------------------------------------------------------------------------------------
	// Process the DBus reply and actually fill the clients_textview
	// -----------------------------------------------------------------------------------------------------

	GVariantIter *iter;
	gchar *str;
	GVariant *reply_body = g_dbus_message_get_body(get_active_clients_reply);
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

		GtkTreeModel *model;
		GtkTreeIter   newrow;

		model = gtk_tree_view_get_model(GTK_TREE_VIEW(clients_treeview));

		gtk_list_store_insert(GTK_LIST_STORE(model), &newrow, -1);

		gtk_list_store_set(GTK_LIST_STORE(model), &newrow, COL_MAC, mac, COL_IP, ip, -1);

		g_free(mac);
		g_free(ip);
		g_free(str_copy);
	}
}

void fill_init_filter_iconview( GtkBuilder		*builder_configure_clients,
							    GDBusMessage	*get_init_filter_reply)
{
	// -----------------------------------------------------------------------------------------------------
	// Now get the init filter
	// -----------------------------------------------------------------------------------------------------
	GObject *icon_view_devices = gtk_builder_get_object (builder_configure_clients, "icon_view_devices");
	GtkTreeModel *icon_view_model = gtk_icon_view_get_model((GtkIconView *)icon_view_devices);

	// -----------------------------------------------------------------------------------------------------
	// Configure Drag and Drop
	// -----------------------------------------------------------------------------------------------------
	GObject *icon_view_filter = gtk_builder_get_object (builder_configure_clients, "icon_view_filter");

	static GtkTargetEntry target_entries[] = {
	   { "GTK_ICON_VIEW_OBJECT", GTK_TARGET_SAME_APP, 0 }
	};

/*
	gtk_drag_source_set((GtkWidget *)icon_view_devices, GDK_BUTTON1_MASK, target, 1, GDK_ACTION_COPY|GDK_ACTION_MOVE);
	gtk_drag_dest_set((GtkWidget*)icon_view_filter, GTK_DEST_DEFAULT_ALL, target, 1, GDK_ACTION_COPY|GDK_ACTION_MOVE);
*/

	gtk_icon_view_enable_model_drag_source( GTK_ICON_VIEW( icon_view_devices ), GDK_BUTTON1_MASK, target_entries, 1, GDK_ACTION_COPY);
	gtk_icon_view_enable_model_drag_dest( GTK_ICON_VIEW( icon_view_filter ), target_entries, 1, GDK_ACTION_COPY);

	g_signal_connect((GtkWidget*)icon_view_filter, "drag-drop", G_CALLBACK( cb_drag_drop ), NULL );
	g_signal_connect((GtkWidget*)icon_view_filter, "drag-data-received", G_CALLBACK( cb_drag_data_received ), NULL );
	g_signal_connect ((GtkWidget*)icon_view_devices, "drag-data-get", G_CALLBACK (cb_drag_data_get), NULL);

	GVariantIter *iter_init_f;
	gchar *str_init_f;
	GtkTreeIter   tree_iter;
	GVariant *reply_body_init_f = g_dbus_message_get_body(get_init_filter_reply);
	g_variant_get (reply_body_init_f, "(as)", &iter_init_f);

	while (g_variant_iter_loop (iter_init_f, "s", &str_init_f))
	{
		gchar *str_copy;
		GdkPixbuf    *pix;

		str_copy = g_strdup_printf("%s", str_init_f);
		g_printf("INIT FILTER LABEL NAME str_copy = %s, str_init_f = %s\n", str_copy, str_init_f);

//		pix = gdk_pixbuf_new(GDK_COLORSPACE_RGB, FALSE, 8, 50, 50);
//		gdk_pixbuf_fill(pix, 0xff000000); /* Red */
		pix = gdk_pixbuf_new_from_file("./pic/bt_logo.png", NULL); //"./pic/client.png"
		GdkPixbuf *new_pix = gdk_pixbuf_scale_simple(pix, 50, 50, GDK_INTERP_BILINEAR);
		gtk_list_store_append(GTK_LIST_STORE(icon_view_model), &tree_iter);
		gtk_list_store_set(GTK_LIST_STORE(icon_view_model), &tree_iter, COL_LABEL, str_copy, COL_ICON, new_pix, -1);
		g_object_unref(G_OBJECT(pix));
		g_object_unref(G_OBJECT(new_pix));

		g_free(str_copy);
	}
}

gboolean create_client_filter_gvariant ( GtkTreeModel	*model,
										 GtkTreePath 	*path,
										 GtkTreeIter 	*iter,
										 gpointer 		 user_data)
{
	GVariantBuilder *g_var_builder = user_data;
	gchar *label;
	gtk_tree_model_get(model, iter, COL_LABEL, &label, -1);
	g_variant_builder_add (g_var_builder, "s", label);
	return FALSE;
}

int set_client_filter( GtkWidget	*widget,
					   gpointer		 data)
{
// Here we should recover the elements from the client filter iconview, create a GVariant body, send DBus message SetClientFilter
	GtkBuilder *builder = data;

	GVariantBuilder g_var_builder;

	gchar *mac = selected_client_info.mac;
	g_variant_builder_init(&g_var_builder, G_VARIANT_TYPE("(sas)"));
	g_variant_builder_add(&g_var_builder, "s", mac);

	g_variant_builder_open(&g_var_builder, G_VARIANT_TYPE("as"));

	GObject *icon_view_filter = gtk_builder_get_object (builder, "icon_view_filter");
	GtkTreeModel *icon_view_model = gtk_icon_view_get_model((GtkIconView *)icon_view_filter);

	gtk_tree_model_foreach(icon_view_model, create_client_filter_gvariant, &g_var_builder);

	g_variant_builder_close(&g_var_builder);

	GVariant *body = g_variant_builder_end(&g_var_builder);
	send_dbus_message("SetClientFilter", body);

	return 0;
}

int configure_clients( GtkWidget *widget,
					   gpointer data)
{
	PRINT_FUNCTION;

	GObject *main_window = data;
/*
	g_printf("===================================================\n");
	g_slist_foreach(builder_list, (GFunc)print_builder_list, NULL);
	g_printf("===================================================\n");
*/
	GtkBuilder *builder_configure_clients = append_new_builder("client_filter_window", "builder_rcm_proxy_configure_clients_win.ui");

	GObject *client_filter_window;

	client_filter_window = gtk_builder_get_object (builder_configure_clients, "client_filter_window");
	g_signal_connect (client_filter_window, "destroy", G_CALLBACK (gtk_window_close), client_filter_window);

	gtk_window_set_transient_for((GtkWindow *)client_filter_window, (GtkWindow *)main_window);

	GObject *validate_button = gtk_builder_get_object(builder_configure_clients, "validate_button");
	g_signal_connect (validate_button, "clicked", G_CALLBACK (set_client_filter), builder_configure_clients);

	// -----------------------------------------------------------------------------------------------------
	// Now fill the active clients treeview: send dbus call GetActiveClients
	// Configure signals: on row activated + Validate button (send gdbus method call SetClientFilter)
	// OnRowActivated should fill the left iconview with the devices from the current init filter
	// It should send GetClientFilter + GetInitFilter
	// -----------------------------------------------------------------------------------------------------

	GDBusMessage *active_clients_reply = send_dbus_request_with_reply("GetActiveClients", NULL);
	if(active_clients_reply != NULL)
		fill_active_clients_treeview(builder_configure_clients, active_clients_reply);

	GDBusMessage *init_filter_reply = send_dbus_request_with_reply("GetInitFilter", NULL);
	if(init_filter_reply != NULL)
		fill_init_filter_iconview(builder_configure_clients, init_filter_reply);

	// -----------------------------------------------------------------------------------------------------
	// Show window
	// -----------------------------------------------------------------------------------------------------

	gtk_widget_show_all ((GtkWidget*)client_filter_window);

	return 0;
}
