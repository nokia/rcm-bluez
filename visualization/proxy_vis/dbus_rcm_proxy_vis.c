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

/*
void on_emit_signal_callback(GDBusConnection *conn,
			     const gchar *sender_name,
			     const gchar *object_path,
			     const gchar *interface_name,
			     const gchar *signal_name,
			     GVariant *parameters,
			     gpointer data)
{
	struct signal_data *info = data;
	GMainLoop *loop = info->loop;
	GObject *gtk_object = info->data;

	gdouble value;
	gchar *value_str;

	g_variant_get (parameters, "(sd)", &value_str, &value);

	g_printf("signal handler: OnEmitSignal received. Args: %s + %d\n", value_str, (int)value);

	gchar *string;

	string = g_strdup_printf ("%g %s\n", value, value_str);

	gtk_text_buffer_insert_at_cursor ((GtkTextBuffer*)gtk_object, string, strlen(string));
//	gtk_label_set_text(label, string);
	g_free (string);
	g_main_loop_quit(loop);
}

void EmitSignal(GObject *gtk_object)
{

	GMainLoop *loop;
	GError          **error = NULL;
	guint id;

	loop = g_main_loop_new(NULL, false);

	struct signal_data data;
	data.loop = loop;
	data.data = gtk_object;

	id = g_dbus_connection_signal_subscribe(dbus_info.conn,
						"org.plugin.RcmServer",
						"org.plugin.RcmInterface",
						"OnEmitSignal",
						"/org/plugin/RcmObject",
						NULL,
						G_DBUS_SIGNAL_FLAGS_NONE,
						on_emit_signal_callback,
						&data,
						NULL);

	GDBusMessage *method_call_message;
	GDBusMessage *method_reply_message;

	method_call_message = NULL;
	method_reply_message = NULL;

	method_call_message = g_dbus_message_new_method_call (dbus_info.name_owner,
				                              "/org/plugin/RcmObject",
				                              "org.plugin.RcmInterface",
				                              "EmitSignal");

	method_reply_message = g_dbus_connection_send_message_with_reply_sync (dbus_info.conn,
		                                                               method_call_message,
		                                                               G_DBUS_SEND_MESSAGE_FLAGS_NONE,
		                                                               -1,
		                                                               NULL,
		                                                               NULL,
		                                                               error);
	if (method_reply_message == NULL)
	goto out;

	if (g_dbus_message_get_message_type (method_reply_message) == G_DBUS_MESSAGE_TYPE_ERROR)
	{
	g_dbus_message_to_gerror (method_reply_message, error);
	goto out;
	}

	g_main_loop_run(loop);
	g_dbus_connection_signal_unsubscribe(dbus_info.conn, id);

 out:
  g_object_unref (method_call_message);
  g_object_unref (method_reply_message);
}
*/
/*
static void
print_hello (GtkWidget *widget,
             gpointer   data)
{
	GObject *gtk_object = data;
	EmitSignal(gtk_object);
}
*/
static struct dbus_data dbus_info;
static struct timeval tv_app_start;
static gboolean initialization_phase = FALSE;		// Indicates whether we are in the initialization phase
static GSList *builder_list;						// List of builders, each element presented as struct builders

struct timeval get_tv_app_start()
{
	return tv_app_start;
}

const gboolean get_initialization_phase()
{
	return initialization_phase;
}

void set_initialization_phase(gboolean status)
{
	initialization_phase = status;
}

GSList *get_builder_list()
{
	return builder_list;
}

struct dbus_data *get_dbus_info()
{
	return &dbus_info;
}

struct timeval get_time()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);

	return tv;
}

int get_builder_for_window(gconstpointer a, gconstpointer b)
{
	PRINT_FUNCTION;

	const struct builders *builders = a;
	const gchar *window_name = b;

	if(strcmp(builders->window_name, window_name) == 0)
		return 0;
	return 1;
}

void print_builder_list(struct builders *builder, gpointer data)
{
	PRINT_FUNCTION;

	g_printf("Builder list: %p for window : %s\n", builder->builder, builder->window_name);
}

GtkBuilder * append_new_builder(gchar *window_name, gchar *builder_ui_file)
{
	GtkBuilder *builder_init;
	GError *error_builder = NULL;

	GSList *builder_list_el = g_slist_find_custom(builder_list, window_name, get_builder_for_window);
	if(builder_list_el != NULL)
	{
		//remove and replace
		remove_builder(builder_list_el->data);
	}

	builder_init = gtk_builder_new ();
	if (gtk_builder_add_from_file(builder_init, builder_ui_file, &error_builder) == 0)
	{
		g_printerr ("Error loading file: %s\n", error_builder->message);
		g_clear_error (&error_builder);
		return NULL;
	}
	struct builders *builder2 = g_malloc(sizeof(struct builders));
	builder2->builder = builder_init;
	builder2->window_name = window_name;

	builder_list = g_slist_append(builder_list, builder2);

	return builder_init;
}

void remove_builder(struct builders* builder)
{
	GtkBuilder *builder_el = builder->builder;
	g_object_unref(builder_el);
	builder_list = g_slist_remove(builder_list, builder);
}
/*
gboolean
draw_callback (GtkWidget *widget, cairo_t *cr, gpointer data)
{
	g_printf("Changing color\n");
  guint width, height;
  GdkRGBA color;
  GtkStyleContext *context;

  context = gtk_widget_get_style_context (widget);

  width = gtk_widget_get_allocated_width (widget);
  height = gtk_widget_get_allocated_height (widget);

  gtk_render_background (context, cr, 0, 0, width, height);

  cairo_arc (cr,
             width / 2.0, height / 2.0,
             MIN (width, height) / 2.0,
             0, 2 * G_PI);

  gtk_style_context_get_color (context,
                               gtk_style_context_get_state (context),
                               &color);

  color.blue = 0.5;
  color.green = 0.5;
  color.red = 0.5;
  color.alpha = 0.5;
  g_printf("Changing color %f %f %f %f\n", color.red, color.blue, color.green, color.alpha);

  gdk_cairo_set_source_rgba (cr, &color);
  cairo_fill (cr);

//  gtk_widget_queue_draw(GTK_WIDGET(widget));
//  gtk_widget_queue_draw(widget);
//  gtk_main_iteration_do(TRUE);

 return FALSE;
}*/

static void free_builder_list_elements( gpointer data)
{
	PRINT_FUNCTION;

	struct builders *element = data;
//	g_free(element->window_name);
	g_object_unref(element->builder);
}

void configure_css()
{
	PRINT_FUNCTION;

	GtkCssProvider *provider;
	GdkDisplay *display;
	GdkScreen *screen;

	provider = gtk_css_provider_new ();
	display = gdk_display_get_default ();
	screen = gdk_display_get_default_screen (display);

	gtk_style_context_add_provider_for_screen (screen, GTK_STYLE_PROVIDER (provider), GTK_STYLE_PROVIDER_PRIORITY_USER);

	const gchar *myCssFile = "style_rcm_proxy_vis.css";
	GError *error_css = 0;

	gtk_css_provider_load_from_file(provider, g_file_new_for_path(myCssFile), &error_css);
	g_object_unref (provider);
}

GObject *get_window(gchar *name)
{
	GObject *window;

	GSList *builder_list = get_builder_list();
	GSList *builder_list_el = g_slist_find_custom(builder_list, "main_window", get_builder_for_window);
	if(builder_list_el == NULL) return NULL;

	struct builders *builders = builder_list_el->data;

	window = gtk_builder_get_object (builders->builder, "main_window");

	return window;
}

int main( int	 argc,
		  gchar *argv[])
{
	PRINT_FUNCTION;

	struct timeval time;

	time = get_time();
	tv_app_start.tv_sec = time.tv_sec;
	tv_app_start.tv_usec = time.tv_usec;

	gtk_init (&argc, &argv);

	initialize_main_window();

	GObject *window = get_window("main_window");
	gtk_widget_show_all ((GtkWidget*)window);
	gtk_main ();

	g_object_unref(dbus_info.conn);
	free_all_main_window();
	g_slist_free_full(builder_list,free_builder_list_elements);

	gdbus_unwatch();
	return 0;
}
