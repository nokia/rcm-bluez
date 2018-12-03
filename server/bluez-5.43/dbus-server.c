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
#include "common.h"

#include <errno.h>

#ifdef G_OS_UNIX
#include <gio/gunixfdlist.h>
/* For STDOUT_FILENO */
#include <unistd.h>
#endif

static GDBusNodeInfo *introspection_data = NULL;
guint owner_id;
gboolean initialization_phase = FALSE;	// Indicates whether we are in the initialization phase

static const gchar introspection_xml[] =
	"<node>\n"

	"  <interface name='org.plugin.RcmInterface'>\n"
	"	<property name='Version' type='s' access='read' />\n"
	"    <method name='IsRcmRunning' >\n"
	"      <arg type='b' direction='out' />\n"
	"    </method>\n"
	"    <method name='StartInitialization' >\n"
	"    </method>\n"
	"    <method name='InitProxyFilter' >\n"
	"		<arg type='as' name='filter_list' direction='in'/>\n"
	"    </method>\n"
	"    <method name='GetActiveClients' >\n"
	"		<arg type='as' name='client_list' direction='out'/>\n"
	"    </method>\n"
	"    <method name='GetInitFilter' >\n"
	"		<arg type='as' name='init_filter' direction='out'/>\n"
	"    </method>\n"
	"    <method name='GetClientFilter' >\n"
	"		<arg type='s' name='client_info' direction='in'/>\n"
	"		<arg type='as' name='client_filter' direction='out'/>\n"
	"    </method>\n"
	"    <method name='SetClientFilter' >\n"
	"		<arg type='s' name='client_mac' direction='in'/>\n"
	"		<arg type='as' name='client_info_filter' direction='in'/>\n"
	"    </method>\n"
	"	 <signal name='NewConnection'>\n"
	"	   <arg type='s' name='ip address' />\n"
	"	   <arg type='s' name='mac address' />\n"
	"	 </signal>\n"
	"	 <signal name='ClientDisconnected'>\n"
	"	   <arg type='s' name='address' />\n"
	"	   <arg type='q' name='port' />\n"
	"	 </signal>\n"
	"	 <signal name='DeviceConnected'>\n"
	"	   <arg type='s' name='device_info' />\n"
	"	 </signal>\n"
	"	 <signal name='DeviceDisconnected'>\n"
	"	   <arg type='s' name='device_info' />\n"
	"	 </signal>\n"
	"	 <signal name='DeviceFound'>\n"
	"	   <arg type='s' name='name' />\n"
	"	   <arg type='s' name='address' />\n"
	"	   <arg type='q' name='address_type' />\n"
	"	   <arg type='b' name='filter_passed' />\n"
	"	 </signal>\n"
	"	 <signal name='RcvRequest'>\n"
	"	   <arg type='s' name='request_type' />\n"
	"	   <arg type='s' name='source' />\n"
	"	 </signal>\n"
	"	 <signal name='SendReply'>\n"
	"	   <arg type='s' name='reply_type' />\n"
	"	   <arg type='s' name='destination' />\n"
	"	 </signal>\n"
	"    <method name='EmitSignal'>\n"
	"    </method>\n"
	"    <signal name='OnEmitSignal'>\n"
	"	   <arg type='d' name='value'/>\n"
	"	   <arg type='s' name='value_str'/>\n"
	"    </signal>"
	"  </interface>\n"

	"</node>\n";

/* ---------------------------------------------------------------------------------------------------- */

static GDBusConnection *gdbus_connection = NULL;
typedef void (*init_cb_t)(void *userdata);
typedef void (*active_clients_cb_t)(void *userdata);
static init_cb_t init_cb = NULL;
static init_cb_t stop_init_discovery_cb = NULL;
static active_clients_cb_t active_clients_cb = NULL;

typedef struct{
	gchar *dev_name;
	gchar *dev_address;
	uint8_t addr_type;
}ConfigEntry;

GSList *init_filter; // contains ConfigEntry elements
gboolean initialized = FALSE;

// Should be callbacks
void get_client_filter(gchar *mac, void *g_v_builder);
void set_client_filter(gchar *mac, ConfigEntry *filter_entry);
GSList * check_autorized(gchar *mac, gchar *address);
void open_the_door();
gboolean connection_exists(gchar *mac);
/* -----------------------------------------------------------------------------------------------------*/
void set_initialized(gboolean new_val)
{
	initialized = new_val;
}

gboolean get_initialized()
{
	return initialized;
}

void make_filter_gvariant( ConfigEntry	*filter_entry,
						   gpointer	 user_data)
{
    TRACE_FUNCTION;

	GVariantBuilder *g_var_builder = user_data;

	gchar * string = g_strdup_printf ("%s,%s", filter_entry->dev_name, filter_entry->dev_address); // TODO: +TYPE!!!
	g_variant_builder_add (g_var_builder, "s", string);
	g_free(string);
}

static void get_init_filter(void *g_v_builder)
{
    TRACE_FUNCTION;

	g_slist_foreach(init_filter, (GFunc)make_filter_gvariant, g_v_builder);

	// Offline testing only!
    /*
	GVariantBuilder *g_var_builder = g_v_builder;

	gchar * string = g_strdup_printf ("%s,%s", "DEV NAME", "DEV ADDRESS");
	g_variant_builder_add (g_var_builder, "s", string);
	g_free(string);
	*/
}

void get_active_clients_cb_register( active_clients_cb_t cb)
{
	TRACE_FUNCTION;

	if(active_clients_cb == NULL)
		active_clients_cb = cb;
	else
		DBG("RCM DBG: get_active_clients callback is already set!");
}

static void get_active_clients_cb_call( active_clients_cb_t	 cb,
										void	   			*userdata)
{
	TRACE_FUNCTION;

	if(cb != NULL)
		(*cb)(userdata);
	else
		DBG("RCM DBG: get_active_clients callback is not set!");
}

void proxy_init_cb_register( init_cb_t cb)
{
	TRACE_FUNCTION;

	if(init_cb == NULL)
		init_cb = cb;
	else
		DBG("RCM DBG: proxy init callback is already set!");
}

static void proxy_init_cb_call( init_cb_t	cb,
								void	   *userdata)
{
	TRACE_FUNCTION;

	if(cb != NULL)
		(*cb)(userdata);
	else
		DBG("RCM DBG: proxy init callback is not set!");
}

static void proxy_stop_init_discovery_cb_call( init_cb_t	cb,
											   void		   *userdata)
{
	TRACE_FUNCTION;

	if(cb != NULL)
		(*cb)(userdata);
	else
		DBG("RCM DBG: proxy_stop_init_discovery_cb is not set!");
}

void proxy_stop_init_discovery_cb_register( init_cb_t cb)
{
	TRACE_FUNCTION;

	if(stop_init_discovery_cb == NULL)
		stop_init_discovery_cb = cb;
	else
		DBG("RCM DBG: proxy_stop_init_discovery_cb is already set!");
}

void send_rcm_gdbus_signal( char		*signal_name,
							GVariant	*signal_data)
{
	TRACE_FUNCTION;

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

// TODO: NOT USED YET
void create_rcm_config_file( gpointer data)
{
	TRACE_FUNCTION;

	FILE *received_file;

	received_file = fopen("rcm_proxy.conf", "w");
	if (received_file == NULL)
	{
		DBG("Failed to open file %s\n", strerror(errno));
		return;
	}
}

void print_init_filter( ConfigEntry	*entry,
							   gpointer		 user_data)
{
    TRACE_FUNCTION;
	g_printf("Device name = %s, address = %s, type = %d\n", entry->dev_name, entry->dev_address, entry->addr_type);
}

static int find_filter_element( gconstpointer a,
								gconstpointer b)
{
	TRACE_FUNCTION;

	const ConfigEntry *entry = a;
	const gchar *address = b;
	if(strcmp(entry->dev_address, address) == 0)
		return 0;
	return 1;
}

static void
handle_method_call( GDBusConnection       *connection,
                    const gchar           *sender,
                    const gchar           *object_path,
                    const gchar           *interface_name,
                    const gchar           *method_name,
                    GVariant              *parameters,
                    GDBusMethodInvocation *invocation,
                    gpointer               user_data)
{
	TRACE_FUNCTION;
	DBG("DBus method name: %s\n", method_name);

	if (g_strcmp0 (method_name, "EmitSignal") == 0)
	{
		GError *local_error;
		gdouble value = 20;
		gchar *value_str;

		//	  value_str = g_strdup_printf ("%g string value", value);
		value_str = g_strdup_printf ("string value");

		local_error = NULL;
		g_dbus_connection_emit_signal (connection,
									   NULL,
									   object_path,
									   interface_name,
									   "OnEmitSignal",
									   g_variant_new ("(sd)",
											   value_str,
											   value),
											   &local_error);
		g_assert_no_error (local_error);
		g_free (value_str);

		g_dbus_method_invocation_return_value (invocation, NULL);
    }
	if (g_strcmp0 (method_name, "StartInitialization") == 0)
	{
		// call START_DISCOVERY
		initialization_phase = TRUE;
		g_dbus_method_invocation_return_value (invocation, NULL);
		proxy_init_cb_call(init_cb, NULL);
	}
	if(g_strcmp0 (method_name, "InitProxyFilter") == 0)
	{
		GVariantIter *iter;
		gchar *str;

		proxy_stop_init_discovery_cb_call(stop_init_discovery_cb, NULL);
		initialization_phase = FALSE; // Once filter list received we are nomore in the initialization phase

		g_variant_get (parameters, "(as)", &iter);
		while (g_variant_iter_loop (iter, "s", &str))
		{
			//g_printf("Got new string: %s\n", str);

			const char delimiters[] = ",";
			gchar *str_copy;
			gchar *token;
			uint8_t type;

//			g_printf("Old filter\n");
//		    g_slist_foreach(init_filter, (GFunc)print_init_filter, NULL);

			ConfigEntry *entry = malloc(sizeof(ConfigEntry));

			str_copy = g_strdup_printf("%s", str);

//			token = strtok(str_copy, delimiters);
//			str_copy is passed in the first call only, next ones will take NULL instead for the same string
//			like this:
//			token = strtok(NULL, delimiters);

			token = strsep(&str_copy, delimiters);
			const gchar *empty_name = "(empty)";
			gboolean ok = is_valid_utf8(token);

			if(ok && strlen(token) != 0)
			{
				entry->dev_name = strdup(token);
			}
			else
			{
				entry->dev_name = strdup(empty_name);
			}

			token = strsep(&str_copy, delimiters);
			entry->dev_address = strdup(token);
			GSList * found_el = g_slist_find_custom(init_filter, token, find_filter_element);

			token = strsep(&str_copy, delimiters);
			entry->addr_type = (uint8_t)atoi(token);

			if (found_el == NULL)
			{
//				DBG("element is not found, add it\n");
				init_filter = g_slist_append(init_filter, entry); // TODO three reactions are possible: add new to the filter, remove some of devices from the filter and replace the whole filter list
			}
			else
			{
//				DBG("element is found, don't add it again\n");
				g_free(entry->dev_name);
				g_free(entry->dev_address);
				g_free(entry);
			}
			g_free(str_copy);
		}
//		g_printf("Current filter\n");
//	    g_slist_foreach(init_filter, (GFunc)print_init_filter, NULL);

	    if(!get_initialized())
	    {
	    	set_initialized(TRUE);
		    // Create the socket and start listening for incoming connections
	    	open_the_door();
	    }
	//	create_rcm_config_file();
		g_variant_iter_free (iter);
	}
	if(g_strcmp0 (method_name, "GetActiveClients") == 0)
	{
		// Create a GVariant container and pass its pointer to the callback
		// like this:
	  	GVariantBuilder g_var_builder;

		g_variant_builder_init(&g_var_builder, G_VARIANT_TYPE("(as)"));
		g_variant_builder_open(&g_var_builder, G_VARIANT_TYPE("as"));

		get_active_clients_cb_call(active_clients_cb, &g_var_builder); // Inside we fill the container with g_slist_for_each

		g_variant_builder_close(&g_var_builder);
		GVariant *string_array = g_variant_builder_end(&g_var_builder);

		g_dbus_method_invocation_return_value(invocation, string_array);
	}
	if(g_strcmp0 (method_name, "GetInitFilter") == 0)
	{
		GVariantBuilder g_var_builder;

		g_variant_builder_init(&g_var_builder, G_VARIANT_TYPE("(as)"));
		g_variant_builder_open(&g_var_builder, G_VARIANT_TYPE("as"));

		get_init_filter(&g_var_builder);

		g_variant_builder_close(&g_var_builder);
		GVariant *string_array = g_variant_builder_end(&g_var_builder);

		g_dbus_method_invocation_return_value(invocation, string_array);
	}
	if(g_strcmp0 (method_name, "GetClientFilter") == 0)
	{
		gchar *mac;
		g_variant_get(parameters, "(s)", &mac);

//		ActiveConnection *get_connection_by_mac_addr( char	*mac_addr)
// cf. GetInitFilter to fill a corresponding GSList in ActiveConnection structure
		GVariantBuilder g_var_builder;

		g_variant_builder_init(&g_var_builder, G_VARIANT_TYPE("(as)"));
		g_variant_builder_open(&g_var_builder, G_VARIANT_TYPE("as"));

		get_client_filter(mac, &g_var_builder);
		g_variant_builder_close(&g_var_builder);
		GVariant *string_array = g_variant_builder_end(&g_var_builder);

//		DBG("return DBus message %p\n", string_array);
		g_dbus_method_invocation_return_value(invocation, string_array);
	}
	if(g_strcmp0 (method_name, "SetClientFilter") == 0)
	{
		GVariantIter *iter;
		gchar *mac;
		gchar *str;

		g_variant_get (parameters, "(sas)", &mac, &iter);
//		DBG("mac = %s\n", mac);
		if(!connection_exists(mac)) return;

		while (g_variant_iter_loop (iter, "s", &str))
		{
//			DBG("info = %s\n", str);

			const char delimiters[] = ",";
			gchar *str_copy;
			gchar *token;
			uint8_t type;

			ConfigEntry *filter_entry = malloc(sizeof(ConfigEntry));

			str_copy = g_strdup_printf("%s", str);

			token = strsep(&str_copy, delimiters);
			filter_entry->dev_name = strdup(token);

			token = strsep(&str_copy, delimiters);
			filter_entry->dev_address = strdup(token);

			GSList * found_el = check_autorized(mac, token);
/*
			token = strsep(&str_copy, delimiters);
			filter_entry->addr_type = (uint8_t)atoi(token);
*/
			if (found_el == NULL)
			{
//				DBG("element is not found, add it\n");
				set_client_filter(mac, filter_entry);
			}
			else
			{
//				DBG("element is found, don't add it again\n");
				g_free(filter_entry->dev_address);
				g_free(filter_entry->dev_name);
				g_free(filter_entry);
			}
			g_free(str_copy);
		}
		g_variant_iter_free (iter);
	}
}

static gboolean handle_set_property( GDBusConnection  *connection,
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

static GVariant * handle_get_property( GDBusConnection  *connection,
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

static const GDBusInterfaceVTable interface_vtable =
{
	handle_method_call,
	handle_get_property,
	handle_set_property
};

static void on_bus_acquired( GDBusConnection *connection,
							 const gchar     *name,
							 gpointer         user_data)
{
	TRACE_FUNCTION;

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

static void on_name_acquired( GDBusConnection *connection,
                  	  	  	  const gchar     *name,
							  gpointer         user_data)
{
	TRACE_FUNCTION;
}

static void on_name_lost( GDBusConnection *connection,
              	  	  	  const gchar     *name,
						  gpointer         user_data)
{
	TRACE_FUNCTION;

	exit (1);
}

void run_rcm_gdbus_server()
{
	TRACE_FUNCTION;

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
	DBG("run_dbus_server %d\n", owner_id);
}

static void free_init_filter( ConfigEntry *entry)
{
	TRACE_FUNCTION;

	g_free(entry->dev_name);
	g_free(entry->dev_address);

	free(entry);
//	g_free(&(entry->addr_type));
}
void stop_rcm_gdbus_server()
{
	TRACE_FUNCTION;

	g_bus_unown_name (owner_id);
	g_dbus_node_info_unref (introspection_data);
	g_slist_free_full(init_filter, (GDestroyNotify)free_init_filter);
	// TODO: free client filters
}

