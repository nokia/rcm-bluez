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

#include <gtk/gtk.h>
#include <stdbool.h>
#include <stdio.h>
#include <glib/gprintf.h>
#include <gio/gio.h>
#include <gdk-pixbuf/gdk-pixbuf.h>
#include <ctype.h>
#include <stdlib.h>
#include  <string.h>

#define M_PI   3.14159265358979323846

struct dbus_data
{
	GDBusProxy *proxy; // for gdbus proxy usage, not used for now
	GDBusConnection *conn;
	const gchar      *name_owner;
};

struct format_result
{
	gchar *error_str;
	gboolean result;
};

struct dbus_data dbus_info;
//GMainLoop *main_loop;

struct signal_data
{
	GMainLoop *loop;
	gpointer data; // basically carries a pointer to GtkLabel inside but may be any other element on the window, so I preferred to be generic.
};

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
	GtkLabel *label = info->data;

	gdouble value;
	gchar *value_str;

	g_variant_get (parameters, "(sd)", &value_str, &value);

	g_printf("signal handler: OnEmitSignal received. Args: %s + %d\n", value_str, (int)value);

	gchar *string;

	string = g_strdup_printf ("%g %s", value, value_str);

	gtk_label_set_text(label, string);
	g_free (string);
	g_main_loop_quit(loop);
}

void EmitSignal(GtkLabel *label)
{

	GMainLoop *loop;
	GError          **error = NULL;
	guint id; /* subscription id */

	loop = g_main_loop_new(NULL, false);

	struct signal_data data;
	data.loop = loop;
	data.data = label;

	id = g_dbus_connection_signal_subscribe(dbus_info.conn,
						"org.plugin.RcmServer",
						"org.plugin.RcmInterface",
						"OnEmitSignal",
						"/org/plugin/RcmObject",
						NULL, /* arg0 */
						G_DBUS_SIGNAL_FLAGS_NONE,
						on_emit_signal_callback,
						&data, /* user data */
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

	g_main_loop_run(loop);
	g_dbus_connection_signal_unsubscribe(dbus_info.conn, id);

 out:
  g_object_unref (method_call_message);
  g_object_unref (method_reply_message);
}
/*
static void
print_hello (GtkWidget *widget,
             gpointer   data)
{
	GtkLabel *label = data;
	EmitSignal(label);
}*/

void show_connection_status (GDBusConnection *conn,
			     const gchar *sender_name,
			     const gchar *object_path,
			     const gchar *interface_name,
			     const gchar *signal_name,
			     GVariant *parameters,
			     gpointer data)
{
	GtkBuilder *builder = data;
	gchar *conn_status;
	g_variant_get (parameters, "(s)", &conn_status);

	GtkTextView * error_label = (GtkTextView*)gtk_builder_get_object (builder, "error_label");
	const char *format = "<span foreground=\"green\">\%s</span>";
	char *markup;
	markup = g_markup_printf_escaped (format, conn_status);
	gtk_label_set_markup (GTK_LABEL (error_label), markup);
	g_free (markup);

//	gtk_label_set_text(error_label, string);
}

static void
on_name_appeared (GDBusConnection *connection,
                  const gchar     *name,
                  const gchar     *name_owner,
                  gpointer         user_data)
{
	dbus_info.name_owner = name_owner;
	dbus_info.conn = connection;
	GtkBuilder *builder = user_data;

	g_dbus_connection_signal_subscribe(dbus_info.conn,
									   "org.plugin.RcmServer",
									   "org.plugin.RcmInterface",
									   "ConnectionStatus",
									   "/org/plugin/RcmObject",
									   NULL, /* arg0 */
									   G_DBUS_SIGNAL_FLAGS_NONE,
									   show_connection_status,
									   builder, /* user data */
									   NULL);
}

static void
on_name_vanished (GDBusConnection *connection,
                  const gchar     *name,
                  gpointer         user_data)
{
	g_printerr ("Failed to get name owner for %s\n"
	      "Is ./gdbus-example-server running?\n",
	      name);
	exit (1);
}

static void
SetProxyConnectionInfo(const gchar *ip, const gchar *port)
{
	g_printf("SetProxyConnectionInfo\n");
	GMainLoop	 *loop;
	GDBusMessage *method_call_message;
	GError       **error = NULL;

	loop = g_main_loop_new(NULL, false);

	method_call_message = NULL;

	method_call_message = g_dbus_message_new_method_call (dbus_info.name_owner,
														  "/org/plugin/RcmObject",
														  "org.plugin.RcmInterface",
														  "SetProxyConnectionInfo");

	g_dbus_message_set_body(method_call_message, g_variant_new("(ss)", ip, port));
	g_printf("SetProxyConnectionInfo set body\n");

	gboolean ok = g_dbus_connection_send_message (dbus_info.conn,
											   	  method_call_message,
												  G_DBUS_SEND_MESSAGE_FLAGS_NONE,
												  NULL, /* out_serial */
												  error);
	g_printf("SetProxyConnectionInfo msg sent ok = %d\n", ok);

	g_main_loop_run(loop);

	g_object_unref(method_call_message);
}

static void
popup_error(GtkBuilder *builder, gchar *ip_msg, gchar *port_msg)
{
	g_printf("popup_error\n");

	GtkLabel *error_label;
/*	GtkButton *popup_ok_button;
	GtkWindow *popup_window;

	popup_window = (GtkWindow *)gtk_builder_get_object (builder, "popup_window");
	popup_label = (GtkLabel *)gtk_builder_get_object (builder, "popup_label");
	popup_ok_button = (GtkButton *)gtk_builder_get_object (builder, "popup_ok_button");

	gtk_label_set_text(popup_label, );
	g_signal_connect (popup_window, "destroy", G_CALLBACK (gtk_widget_destroy), NULL);

	g_signal_connect (popup_ok_button, "clicked", G_CALLBACK (gtk_widget_destroy), popup_window);
	gtk_widget_show_all ((GtkWidget*)popup_window);
*/
	error_label = (GtkLabel *)gtk_builder_get_object (builder, "error_label");
	gchar *string = g_strdup_printf ("IP address: %sPort: %s", ip_msg, port_msg);
	gtk_label_set_text(error_label, string);
	g_free(string);
}

static struct format_result
check_format(const gchar *string, int length, gchar authorized_symbol)
{
	g_printf("is_numeric\n");
	struct format_result result;
	int number;
	int j = 0;
	char ip_number [2];
	gboolean auth_char_last = FALSE;
	int nb_dots = 0;

	if(length == 0)
	{
		result.error_str = "Empty field\n";
		result.result = FALSE;
		return result;
	}

	for (int i=0; i<length; i++)
	{
		if(!isdigit(string[i]))
		{

			if(authorized_symbol != '\0' && string[i] != authorized_symbol)
			{
				result.error_str = "Check formats:\n\t ip address: [0-255].[0-255].[0-255].[0-255]\n\t port: digits only\n";
				result.result = FALSE;
				return result;
			}
			else if(authorized_symbol != '\0' && string[i] == authorized_symbol)
			{
				j = 0;
				nb_dots++;
				if((i == length - 1) || (i == 0))
				{
					result.error_str = "IP address is not finished?\n";
					result.result = FALSE;
					return result;
				}
				if(auth_char_last)
				{
					result.error_str = "IP address is not finished? Sequence of \".\" detected\n";
					result.result = FALSE;
					return result;
				}
				if(nb_dots > 3)
				{
					result.error_str = "Too many dots in IP address: %d \".\" detected\n";
					result.result = FALSE;
					return result;
				}

				auth_char_last = TRUE;
			}
			else if(authorized_symbol == '\0')
			{
				result.error_str = "Check port string format\n\t port: digits only\n";
				result.result = FALSE;
				return result;
			}
		}
		else
		{
			auth_char_last = FALSE;

			if(authorized_symbol != '\0')
			{
				g_printf("is_numeric = %c\n", string[i]);
				if(j >= 3)
				{
					g_printf("j > 3 = %c\n", string[i]);

					result.error_str = "Too huge number in IP address?\n";
					result.result = FALSE;
					return result;
				}
				else
				{
					g_printf("j <= 3 = %c\n", string[i]);

					ip_number[j] = string[i];
					j++;
					if(j == 3)
					{
						number = atoi(ip_number);
						g_printf("j == 3 = %c > %d = %s\n", string[i], number, ip_number);

						if(number > 255)
						{
							result.error_str = "One of the value > 255:\n\t ip address: [0-255].[0-255].[0-255].[0-255]\n";
							result.result = FALSE;
							return result;
						}
					}
				}
			}
		}
	}
	if(authorized_symbol != '\0' && nb_dots == 0)
	{
		result.error_str = "IP address is not finished?\n\t ip address: [0-255].[0-255].[0-255].[0-255]\n";
		result.result = FALSE;
	}
	else
	{
		result.error_str = "Format passed\n";
		result.result = TRUE;
	}
	return result;
}

static void
get_ip_and_port(GtkWidget *widget,
				gpointer   data)
{
	g_printf("get_ip_and_port\n");

	GtkBuilder *builder = data;

	GtkEntry *entry_ip_addr;
	GtkEntry *entry_port;
	GtkLabel *error_label;
	struct format_result ip_ok;
	struct format_result port_ok;

	entry_ip_addr = (GtkEntry *)gtk_builder_get_object (builder, "entry_ip_addr");
	entry_port = (GtkEntry *)gtk_builder_get_object (builder, "entry_port");

	error_label = (GtkLabel *)gtk_builder_get_object (builder, "error_label");
	gtk_label_set_text(error_label, "");

	const gchar *ip_addr = gtk_entry_get_text(entry_ip_addr);
	const gchar *port = gtk_entry_get_text(entry_port);

	int length;
	length = strlen (ip_addr);
	g_printf("get_ip_and_port: ip = %s port = %s, length ip = %d\n", ip_addr, port, length);

	if(length > 15)
	{
		g_print("Too many characters in IP address string, %d < 15\n", length);
		ip_ok.error_str = "Too many characters in IP address string\n";
		ip_ok.result = FALSE;
	}
	else
	{
		g_printf("checking format for ip\n");
		ip_ok = check_format(ip_addr, length, '.');
		g_printf("%s\n", ip_ok.error_str);
	}
	length = strlen (port);
	g_printf("checking format fo port\n");
	port_ok = check_format(port, length, '\0');
	g_printf("%s", port_ok.error_str);
	g_printf("results: %d %d\n", port_ok.result, ip_ok.result);

	if(port_ok.result == FALSE || ip_ok.result == FALSE)
	{
		g_printf("results: %d %d\n", port_ok.result, ip_ok.result);
		popup_error(builder, ip_ok.error_str, port_ok.error_str);
		return;
	}

	SetProxyConnectionInfo(ip_addr, port);
	g_printf("results: %d %d\n", port_ok.result, ip_ok.result);
}

void fix_visual(GtkWidget *w)
{
	g_printf("Inside fix_visual\n");
    GdkScreen *screen = gtk_widget_get_screen (w);
    GdkVisual *visual = gdk_screen_get_rgba_visual (screen);
    gtk_widget_set_visual(w, visual);
    //FIXME cleanup maybe
}

void screen_changed (GtkWidget *widget, GdkScreen *screen, gpointer user_data)
{
	g_printf("Inside screen_changed\n");
    fix_visual (widget);
}

int
main (int   argc,
      char *argv[])
{
	GtkBuilder *builder;
	GObject *window;
	GObject *button_connect;
	GError *error = NULL;

	gtk_init (&argc, &argv);

/* Construct a GtkBuilder instance and load our UI description */
	builder = gtk_builder_new ();

	if (gtk_builder_add_from_file (builder, "builder_rcm_client.ui", &error) == 0)
	{
	g_printerr ("Error loading file: %s\n", error->message);
	g_clear_error (&error);
	return 1;
	}

	guint watcher_id;

	watcher_id = g_bus_watch_name (G_BUS_TYPE_SYSTEM,
								   "org.plugin.RcmServer",
								   G_BUS_NAME_WATCHER_FLAGS_NONE,
								   on_name_appeared,
								   on_name_vanished,
								   builder,
								   NULL);

	window = gtk_builder_get_object (builder, "main_window");
	gtk_widget_set_app_paintable ((GtkWidget *)window, FALSE);
	g_signal_connect (window, "destroy", G_CALLBACK (gtk_main_quit), NULL);

	GObject *header;
	header = gtk_builder_get_object(builder, "header_bar");
	gtk_header_bar_set_show_close_button((GtkHeaderBar *)header, TRUE);

// ---------------------------------------------------- CSS -----------------------------------------------------------
	GtkCssProvider *provider;
	GdkDisplay *display;
	GdkScreen *screen;

	provider = gtk_css_provider_new ();
	display = gdk_display_get_default ();
	screen = gdk_display_get_default_screen (display);

	gtk_style_context_add_provider_for_screen (screen, GTK_STYLE_PROVIDER (provider), GTK_STYLE_PROVIDER_PRIORITY_USER);

	const gchar *myCssFile = "style_rcm_client_vis.css";
	GError *error_css = 0;

	gtk_css_provider_load_from_file(provider, g_file_new_for_path(myCssFile), &error_css);
	g_object_unref (provider);
// --------------------------------------------------------------------------------------------------------------------

	button_connect = gtk_builder_get_object (builder, "button_connect");
	g_signal_connect (button_connect, "clicked", G_CALLBACK (get_ip_and_port), builder);

	fix_visual ((GtkWidget*)window);

	gtk_widget_show_all ((GtkWidget*)window);
	gtk_main ();

	g_object_unref(dbus_info.conn);

	g_bus_unwatch_name (watcher_id);
	return 0;
}
