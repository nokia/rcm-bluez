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

void send_dbus_message( gchar	 *method_name,
					    GVariant *body)
{
	PRINT_FUNCTION;

	// Here we should send a Method call to our server
	g_printf("Sending dbus message %s %p\n", method_name, body);

	struct dbus_data *dbus_info = get_dbus_info();

	g_dbus_connection_call(dbus_info->conn,
			 	 	 	   dbus_info->name_owner,
						   "/org/plugin/RcmObject",
						   "org.plugin.RcmInterface",
						   method_name,
						   body,
						   NULL,
						   G_DBUS_CALL_FLAGS_NONE,
						   -1,
						   NULL,
						   NULL,
						   NULL);
}
//void
gboolean print_selection ( GtkTreeModel	*model,
						   GtkTreePath 	*path,
						   GtkTreeIter 	*iter,
						   gpointer 	 data)
{
	PRINT_FUNCTION;

	gboolean enabled;
	gchar * name = "?";
	gtk_tree_model_get(model, iter, COL_ADD, &enabled, COL_NAME, &name, -1);
	g_printf("enabled = %d name = %s\n", enabled, name);

	return FALSE;
}

gboolean add_to_filter ( GtkTreeModel	*model,
					     GtkTreePath 	*path,
						 GtkTreeIter 	*iter,
						 gpointer 		 user_data)
{
	PRINT_FUNCTION;

	GVariantBuilder *g_var_builder = user_data;
	g_printf("add_to_filter g_var_builder = %p\n", g_var_builder);

	gboolean enabled;
	gchar * name = "?";
	gchar * address = "?";
	gchar * type = "?";

	gtk_tree_model_get(model, iter, COL_ADD, &enabled, COL_NAME, &name, COL_ADDRESS, &address, COL_TYPE_INT, &type, -1);

	if(enabled)
	{
		g_printf("enabled = %d name = %s address = %s type = %s\n", enabled, name, address, type);
		gchar * string = g_strdup_printf ("%s,%s,%s", name, address, type);
		g_variant_builder_add (g_var_builder, "s", string);
		g_free(string);
	}
	return FALSE;
}

// This function will be called when Filter button is pressed
// Here we should recover the selected entries from our ListBox
// Create a file with the corresponding info to be able to show the saved filter info
// Send the filter to the proxy
static void send_filtered_list ( GtkWidget	*widget,
								 gpointer	 data)
{
	PRINT_FUNCTION;

	GSList *builder_list_el;

	set_initialization_phase(FALSE);

	GSList *builder_list = get_builder_list();
	builder_list_el = g_slist_find_custom(builder_list, "proxy_init_window", get_builder_for_window);
	if(builder_list_el == NULL) return;
	struct builders *builders = builder_list_el->data;

	GObject *treeview_init_filter = gtk_builder_get_object (builders->builder, "treeview_init_filter");
	GtkTreeModel *treeview_model = gtk_tree_view_get_model((GtkTreeView *)treeview_init_filter);

  	GVariantBuilder g_var_builder;

	g_variant_builder_init(&g_var_builder, G_VARIANT_TYPE("(as)"));
	g_variant_builder_open(&g_var_builder, G_VARIANT_TYPE("as"));

	gtk_tree_model_foreach(treeview_model, add_to_filter, &g_var_builder);

	g_variant_builder_close(&g_var_builder);
	GVariant *string_array = g_variant_builder_end(&g_var_builder);

	send_dbus_message("InitProxyFilter", string_array);
}


gboolean can_show ( GtkTreeModel *model,
				    GtkTreePath  *path,
				    GtkTreeIter  *iter,
				    gpointer 	 user_data)
{
	PRINT_FUNCTION;

	g_printf("Check whether the device is alredy shown\n");
	DeviceInfo *dev_info = user_data;

	gboolean enabled;
	gchar * name = "?";
	gchar * address = "?";
	gchar * type = "?";

	gtk_tree_model_get(model, iter, COL_ADD, &enabled, COL_NAME, &name, COL_ADDRESS, &address, COL_TYPE_INT, &type, -1);
	g_printf("From TreeModel: enabled = %d name = %s address = %s type = %s\n", enabled, name, address, type);
	g_printf("From DeviceInfo: name = %s address = %s type = %d\n",dev_info->dev_name, dev_info->dev_addr, dev_info->addr_type);

	if(strcmp(address, dev_info->dev_addr) == 0 && atoi(type) == dev_info->addr_type)
	{
		g_printf("device is already shown, return\n");
		if((strlen(name) == 0 || strcmp(name, "[Invalid UTF-8]") == 0) &&
		   (strlen(dev_info->dev_name) != 0 && strcmp(dev_info->dev_name, "[Invalid UTF-8]") != 0))
			gtk_list_store_set(GTK_LIST_STORE(model), iter, COL_NAME, &dev_info->dev_name, -1); // TODO: do the same on dbus-server side ?
																								// TODO: Implement add/remove/replace functionalities with config file

		dev_info->shown = TRUE;
		return TRUE;
	}
	g_printf("device is not shown yet\n");
	return FALSE;
}

// To add a de new CheckButton widget as a ListBox entry
// TODO: need to find how to align the label and the check button...
// For now I didn't find how to get the GtkLabel object from GTKCheckButton (or even from higher hierarchy like GtkButton...)
// It is only possible to get char * containing the current value stored in this label but not the object itself.
void add_init_device( GtkBuilder *builder,
					  gchar 	 *dev_name,
					  gchar 	 *dev_addr,
					  guint16	  addr_type)
{
	PRINT_FUNCTION;

	g_printf("[add_init_device]\n");
	GtkTreeModel *model;
	GtkTreeIter   newrow;
	GObject *treeview = gtk_builder_get_object (builder, "treeview_init_filter");

	model = gtk_tree_view_get_model(GTK_TREE_VIEW(treeview));
	g_printf("treeview = %p, model = %p\n", treeview, model);

	gchar *addr_type_str = g_strdup_printf("%d", addr_type);

	DeviceInfo dev_info;
	dev_info.dev_name = dev_name;
	dev_info.dev_addr = dev_addr;
	dev_info.addr_type = addr_type;
	dev_info.shown = FALSE;

	gtk_tree_model_foreach(model, can_show, &dev_info);

	if(dev_info.shown)
	{
		return;
	}

	gtk_list_store_insert(GTK_LIST_STORE(model), &newrow, -1);

	gtk_list_store_set(GTK_LIST_STORE(model), &newrow,
													   COL_ADD, FALSE,
													   COL_NAME, dev_name,
													   COL_ADDRESS, dev_addr,
													   COL_TYPE_INT, addr_type_str,
													   COL_TYPE_STR, addr_type==0?"BDADDR_BREDR":addr_type==1?"BDADDR_LE_PUBLIC":addr_type==2?"BDADDR_LE_RANDOM":"UNKNOWN", -1);

	g_free(addr_type_str);
}

// ==============================================================================
// This is the test function to fill the ListBox
// FREE, NOT USED, USE IT FOR TEST
void test_callback_init ( GtkWidget *widget,
						  gpointer   data)
{
	PRINT_FUNCTION;

	GSList *builder_list = get_builder_list();
	GSList *builder_list_el = g_slist_find_custom(builder_list, "proxy_init_window", get_builder_for_window);
	if(builder_list_el == NULL) return;

	struct builders *builders = builder_list_el->data;
	g_printf("[test_callback_init] builder = %p\n", builders->builder);
	add_init_device(builders->builder, "My device", "device_address", 1);
}
// ==============================================================================
/*
GtkWidget * create_view_and_model()
{
	GtkCellRenderer    *renderer;
	GtkListStore       *liststore;
	GtkWidget          *view;

	liststore = gtk_list_store_new(NUM_COLS, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING); // NUM_COLS = 3

	view = gtk_tree_view_new_with_model(GTK_TREE_MODEL(liststore));

	 // --- Column #1 ---

	  renderer = gtk_cell_renderer_text_new ();
	  gtk_tree_view_insert_column_with_attributes (GTK_TREE_VIEW (view),
	                                               -1,
	                                               "Name",
	                                               renderer,
	                                               "text", COL_NAME,
	                                               NULL);

	  // --- Column #2 ---

	  renderer = gtk_cell_renderer_text_new ();
	  gtk_tree_view_insert_column_with_attributes (GTK_TREE_VIEW (view),
	                                               -1,
	                                               "Address",
	                                               renderer,
	                                               "text", COL_ADDRESS,
	                                               NULL);

	  renderer = gtk_cell_renderer_text_new ();
	  gtk_tree_view_insert_column_with_attributes (GTK_TREE_VIEW (view),
	                                               -1,
	                                               "Type",
	                                               renderer,
	                                               "text", COL_TYPE_INT,
	                                               NULL);

	return view;
}*/

void on_row_activated( GtkTreeView       *tree_view,
					   GtkTreePath       *path,
					   GtkTreeViewColumn *column,
					   gpointer           user_data)
{
	PRINT_FUNCTION;

    GtkWindow * win_main = GTK_WINDOW(user_data);
    g_print("on_row_activated: path = %s user_data = %p\n", gtk_tree_path_to_string(path), win_main);
}

void on_toggle( GtkCellRendererToggle *cell_renderer,
				gchar                 *path,
				gpointer               user_data)
{
	PRINT_FUNCTION;

    GObject * liststore1 = user_data;
    GtkTreeIter iter;

    gboolean active = gtk_cell_renderer_toggle_get_active(cell_renderer);

    gtk_tree_model_get_iter_from_string (GTK_TREE_MODEL (liststore1), &iter, path);

    if (active) {
//    	gtk_cell_renderer_set_alignment(GTK_CELL_RENDERER(cell_renderer), 0, 0);
    	gtk_list_store_set (GTK_LIST_STORE (liststore1), &iter, COL_ADD, FALSE, -1);
    }
    else {
//    	gtk_cell_renderer_set_alignment(GTK_CELL_RENDERER(cell_renderer), 0, 0);
    	gtk_list_store_set (GTK_LIST_STORE (liststore1), &iter, COL_ADD, TRUE, -1);
    }
}

// Called when Initialize button is pressed
// TODO: recover the current configuration of the proxy filter and fill the ListBox accordingly
// For the moment, it always creates a new empty ListBox and sends StartInitialization to the proxy
// in order to fill the list.
int proxy_init ( GtkWidget *widget,
 				 gpointer   data)
{
	PRINT_FUNCTION;

	g_printf("proxy_init\n");

	GObject *main_window = data;
	/*
	GtkBuilder *builder_init;
	GError *error_builder = NULL;
	*/
/*
	g_printf("===================================================\n");
	g_slist_foreach(builder_list, (GFunc)print_builder_list, NULL);
	g_printf("===================================================\n");
*/
	/*
	GSList *builder_list = get_builder_list();
	GSList *builder_list_el = g_slist_find_custom(builder_list, "proxy_init_window", get_builder_for_window);
	if(builder_list_el != NULL)
	{
		//remove
		remove_builder(builder_list_el->data);
	}
	builder_init = gtk_builder_new ();
	if (gtk_builder_add_from_file(builder_init, "builder_rcm_proxy_init_win_liststore.ui", &error_builder) == 0)
	{
		g_printerr ("Error loading file: %s\n", error_builder->message);
		g_clear_error (&error_builder);
		return 1;
	}
	struct builders *builder2 = g_malloc(sizeof(struct builders));
	builder2->builder = builder_init;
	builder2->window_name = "proxy_init_window";
	*/
	GtkBuilder *builder_init = append_new_builder("proxy_init_window", "builder_rcm_proxy_init_win_liststore.ui");
//	builder_list = g_slist_append(builder_list, builder2);
/*
	g_printf("===================================================\n");
	g_slist_foreach(builder_list, (GFunc)print_builder_list, NULL);
	g_printf("===================================================\n");
*/
	GObject *proxy_init_window;
	GObject *filter_button;
	GObject *treeview_init_filter;

	proxy_init_window = gtk_builder_get_object (builder_init, "proxy_init_window");
	g_signal_connect (proxy_init_window, "destroy", G_CALLBACK (gtk_window_close), proxy_init_window);

	gtk_window_set_transient_for((GtkWindow *)proxy_init_window, (GtkWindow *)main_window);

	treeview_init_filter = gtk_builder_get_object (builder_init, "treeview_init_filter");
	g_signal_connect(treeview_init_filter, "row-activated", G_CALLBACK(on_row_activated), proxy_init_window);

	GObject * init_filter_check_renderer = gtk_builder_get_object(builder_init, "init_filter_check_renderer");
	GObject * liststore1 = gtk_builder_get_object(builder_init, "liststore1");
	g_signal_connect(init_filter_check_renderer, "toggled", G_CALLBACK(on_toggle), liststore1);

	filter_button = gtk_builder_get_object (builder_init, "filter_button");
	g_signal_connect (filter_button, "clicked", G_CALLBACK (send_filtered_list), NULL);

	// Here we should send a Method call to our DBus server
	GError       **error = NULL;
	GDBusMessage *method_call_message;
	GDBusMessage *method_reply_message;

	method_call_message = NULL;
	method_reply_message = NULL;

	struct dbus_data *dbus_info = get_dbus_info();

	method_call_message = g_dbus_message_new_method_call (dbus_info->name_owner,
														  "/org/plugin/RcmObject",
														  "org.plugin.RcmInterface",
														  "StartInitialization");

	method_reply_message = g_dbus_connection_send_message_with_reply_sync (dbus_info->conn,
			                                                               method_call_message,
			                                                               G_DBUS_SEND_MESSAGE_FLAGS_NONE,
			                                                               -1,
			                                                               NULL, /* out_serial */
			                                                               NULL, /* cancellable */
			                                                               error);
	if (method_reply_message == NULL)
		goto out;

	if (g_dbus_message_get_message_type (method_reply_message) == G_DBUS_MESSAGE_TYPE_ERROR)
	{
		g_dbus_message_to_gerror (method_reply_message, error);
		goto out;
	}

	set_initialization_phase(TRUE);

	gtk_widget_show_all ((GtkWidget*)proxy_init_window);

out:
	g_object_unref (method_call_message);
	g_object_unref (method_reply_message);

return 0;
}
