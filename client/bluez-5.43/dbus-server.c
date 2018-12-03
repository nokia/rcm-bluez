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

#include <gio/gio.h>
#include <stdlib.h>
#include <glib/gprintf.h>

#include "dbus-server.h"

#ifdef G_OS_UNIX
#include <gio/gunixfdlist.h>
/* For STDOUT_FILENO */
#include <unistd.h>
#endif

static GDBusNodeInfo *introspection_data = NULL;
guint owner_id;

static const gchar introspection_xml[] =
	"<node>\n"

	"  <interface name='org.plugin.RcmInterface'>\n"
	"	<property name='Version' type='s' access='read' />\n"
	"    <method name='SetProxyConnectionInfo'>\n"
	"	   <arg type='s' name='ip_address'/>\n"
	"	   <arg type='s' name='port'/>\n"
	"    </method>\n"
	"	 <signal name='ConnectionStatus'>\n"
	"	   <arg type='s' name='status' />\n"
	"	 </signal>\n"

	"  </interface>\n"

	"</node>\n";

/* ---------------------------------------------------------------------------------------------------- */
static GDBusConnection *gdbus_connection = NULL;

void rcm_connection_cb_register(conn_info_t cb)
{
	if(conn_info == NULL)
		conn_info = cb;
	else
		DBG("Connection callback is already set!");
}

static void rcm_connection_cb_call(conn_info_t cb, void *userdata)
{
	DBG("call connection callback");
	if(cb != NULL)
		(*cb)(userdata);
	else
		DBG("Connection callback is not set!");
}

void send_rcm_gdbus_signal(char *signal_name, GVariant *signal_data)
{
	DBG("Sending signal %s\n", signal_name);
	GError *local_error;

	local_error = NULL;
	g_dbus_connection_emit_signal (gdbus_connection,
								   NULL,
								   RCM_OBJECT_PATH,
								   RCM_INTERFACE_NAME,
								   signal_name,
								   signal_data,
								   &local_error);

	g_assert_no_error (local_error);
}

static void
handle_method_call (GDBusConnection       *connection,
                    const gchar           *sender,
                    const gchar           *object_path,
                    const gchar           *interface_name,
                    const gchar           *method_name,
                    GVariant              *parameters,
                    GDBusMethodInvocation *invocation,
                    gpointer               user_data)
{
	DBG("handle_method_call: object_path = %s, interface_name=%s method_name=%s\n", object_path, interface_name, method_name);

	if (g_strcmp0 (method_name, "SetProxyConnectionInfo") == 0)
	{
		gchar *ip;
		gchar *port;
		g_variant_get (parameters, "(ss)", &ip, &port);
		g_printf("got ip=%s and port=%s\n", ip, port);

		struct connection conn;
		conn.ip_address = ip;
		conn.port = port;
		rcm_connection_cb_call(conn_info, &conn);

		g_free (ip);

		g_dbus_method_invocation_return_value (invocation, NULL);

	}
}

static gboolean
handle_set_property (GDBusConnection  *connection,
                     const gchar      *sender,
                     const gchar      *object_path,
                     const gchar      *interface_name,
                     const gchar      *property_name,
                     GVariant         *value,
                     GError          **error,
                     gpointer          user_data)
{
	return FALSE;
//
}

static GVariant *
handle_get_property (GDBusConnection  *connection,
                     const gchar      *sender,
                     const gchar      *object_path,
                     const gchar      *interface_name,
                     const gchar      *property_name,
                     GError          **error,
                     gpointer          user_data)
{
	return FALSE;
//
}

/* for now */
static const GDBusInterfaceVTable interface_vtable =
{
	handle_method_call,
	handle_get_property,
	handle_set_property
};

/* ---------------------------------------------------------------------------------------------------- */

static void
on_bus_acquired (GDBusConnection *connection,
                 const gchar     *name,
                 gpointer         user_data)
{
	DBG("Registering name\n");
	guint registration_id;
	gdbus_connection = connection;

	registration_id = g_dbus_connection_register_object (connection,
			                                     "/org/plugin/RcmObject",
			                                     introspection_data->interfaces[0],
			                                     &interface_vtable,
			                                     NULL,  /* user_data */
			                                     NULL,  /* user_data_free_func */
			                                     NULL); /* GError** */
	DBG("registration_id = %d\n", registration_id);
	g_assert (registration_id > 0);

	DBG("Name successfully registered\n");
}

static void
on_name_acquired (GDBusConnection *connection,
                  const gchar     *name,
                  gpointer         user_data)
{
}

static void
on_name_lost (GDBusConnection *connection,
              const gchar     *name,
              gpointer         user_data)
{
  exit (1);
}

void run_rcm_gdbus_server()
{
	DBG("run_dbus_server\n");
//	GMainLoop *loop;
	introspection_data = g_dbus_node_info_new_for_xml (introspection_xml, NULL);
	g_assert (introspection_data != NULL);

	owner_id = g_bus_own_name (G_BUS_TYPE_SYSTEM,
							   "org.plugin.RcmServer",
							   G_BUS_NAME_OWNER_FLAGS_NONE,
							   on_bus_acquired,
							   on_name_acquired,
							   on_name_lost,
							   NULL,
							   NULL);
	DBG("dbus server ozner id=%d\n", owner_id);

//	loop = g_main_loop_new (NULL, FALSE);
//	g_main_loop_run (loop);
}

void stop_rcm_gdbus_server()
{
	g_bus_unown_name (owner_id);
	g_dbus_node_info_unref (introspection_data);
}
/*
int
main (int argc, char *argv[])
{
	GMainLoop *loop;

	run_dbus_server();

	loop = g_main_loop_new (NULL, FALSE);
	g_main_loop_run (loop);

	stop_dbus_server();
//	g_bus_unown_name (owner_id);

//	g_dbus_node_info_unref (introspection_data);

	return 0;
}
*/
