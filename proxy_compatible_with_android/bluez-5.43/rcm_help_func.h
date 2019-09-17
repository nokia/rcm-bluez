/* 	Remote Connection Manager - is a research prototype of the
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
	Marc-Olivier Buob <marc-olivier.buob@nokia-bell-labs.com>
	Hui YIN <phoebe_yin@msn.com>
*/

#ifndef SERVER_BLUEZ_5_43_RCM_HELP_FUNC_H_
#define SERVER_BLUEZ_5_43_RCM_HELP_FUNC_H_

#include "rcm_structures.h"
#include "common.h"

//==========================================================================
// Printing
void print_fd(GSocketConnection *conn, const char *func){
	GSocket *socket = g_socket_connection_get_socket(conn);
	int fd = g_socket_get_fd(socket);
	printf("SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS\n");
	printf("%s connection = %p socket fd = %d\n",func, conn, fd);
	printf("SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS\n");
}

void print_mapping_element(BTAddrMapping *element)
{
        printf("Real: ");
        for(int i=0; i<6; i++)
                printf("%02x ", element->real_bdaddr.b[i]);

        printf("Virt: ");
        for(int i=0; i<6; i++)
                printf("%02x ", element->virt_bdaddr[i]);

        printf("Connection %p\n", element->connection);

        printf("\n");
}

//==========================================================================
// BT address mapping
int find_mapping_real(gconstpointer a, gconstpointer b){
        const BTAddrMapping *el = (BTAddrMapping *)a;
        const bdaddr_t *addr = (bdaddr_t *)b;
        for(int i=0; i<6; i++){
                if(el->real_bdaddr.b[i] != addr->b[i])
                        return -1;
        }
return 0;
}

int find_mapping_virt(gconstpointer a, gconstpointer b){
        const BTAddrMapping *el = (BTAddrMapping *)a;
        const uint8_t *addr = (uint8_t *)b;
        for(int i=0; i<6; i++){
                if(el->virt_bdaddr[i] != addr[i])
                        return -1;
        }
return 0;
}

BTAddrMapping * map_address(const bdaddr_t *addr)
{
        GSList *l = g_slist_find_custom(addr_mapping_list, addr, find_mapping_real);
        if(l) return (BTAddrMapping *)l->data;

        BTAddrMapping *new_item = (BTAddrMapping *) malloc(sizeof(BTAddrMapping));
        if(!new_item) return NULL;

        memcpy(&(new_item->real_bdaddr), addr, 6);
        free_device_id++;
        dev_id_base[5] = free_device_id;
        memcpy(&(new_item->virt_bdaddr), &dev_id_base, 6);

        new_item->connection = NULL;
        addr_mapping_list = g_slist_append(addr_mapping_list, new_item);
        return new_item;
}

int connection_mapped(gconstpointer a, gconstpointer b){
	const BTAddrMapping *el = (BTAddrMapping *)a;
	const GSocketConnection *conn = (GSocketConnection *)b;

	if(el->connection == conn)
		return 0;
	return -1;
}

//==========================================================================
// Free memory
void clean_mapping_element(BTAddrMapping *item)
{
        free(&item->real_bdaddr);
        free(&item->virt_bdaddr);
        free(item);
}

//==========================================================================
// Checking
gboolean rcm_connection_exists(gchar *mac)
{
	ActiveClient *connection = get_client_by_mac_addr(mac);
	if(!connection) return FALSE;
	return TRUE;
}

GSList * rcm_check_autorized(gchar *mac, gchar *address)
{
	ActiveClient *connection = get_client_by_mac_addr(mac);
	if(!connection) return NULL;

	return g_slist_find_custom(connection->authorized_devices, address,	rcm_gdbus_find_filter_element);
}
// Not used
gboolean rcm_ignore_discovery(GSocketConnection *connection)
{
	GSList *l = g_slist_find_custom(addr_mapping_list, connection, connection_mapped);
	if(!l) return FALSE;
	return TRUE;
}
//==========================================================================


//==========================================================================
// Getters
void rcm_get_client_filter(gchar *mac, void *g_v_builder)
{
    TRACE_FUNCTION;

    ActiveClient *connection = get_client_by_mac_addr(mac);

    if(!connection || connection->authorized_devices == NULL)
    {
    	g_variant_builder_add ((GVariantBuilder *)g_v_builder, "s", "empty");
    	return;
    }

    g_slist_foreach(connection->authorized_devices, (GFunc)make_filter_gvariant, g_v_builder);
}

//==========================================================================
// Commands
void rcm_authorize_device(gchar *mac, ConfigEntry *filter_entry)
{
	TRACE_FUNCTION;

	ActiveClient *connection = get_client_by_mac_addr(mac);
	if(!connection)
		return;

	connection->authorized_devices = g_slist_append(connection->authorized_devices, filter_entry);
}

//==========================================================================
// Tracing (NOT USED)
void rcm_create_trace_file()
{
    TRACE_FUNCTION;
	// Let's create a file to keep tracing
	const char* dir = "./result_traces/";
	const char* file_name = "connection_delay_trace";
	const size_t path_size = strlen(dir) + strlen(file_name) + 1;
	path_to_trace = malloc(path_size);
	if(path_to_trace)
	{
		snprintf(path_to_trace, path_size, "%s%s", dir, file_name);
	}
	else
		DBG("No path_to_trace!!!");
}

void rcm_open_trace_file()
{
    TRACE_FUNCTION;
	trace_file = fopen(path_to_trace, "ab+"); // Open for read, write and create the file if necessary

	if(!trace_file)
	{
		DBG("Failed to open the trace file ! %s", path_to_trace);
		exit(1);
	}
	else
	{
		DBG("Trace file is successfully opened!");
	}
}

void rcm_write_trace()
{
    TRACE_FUNCTION;
	if(!trace_file)
		rcm_open_trace_file();

	timersub(&tv_recv, &tv_send, &tv_diff);
	fprintf(trace_file, "%.6f %.6f %.6f ms %ld.%06ld %ld.%06ld %ld.%06ld mks\n", tv2fl(tv_send), tv2fl(tv_recv), tv2fl(tv_diff),
																					tv_send.tv_sec, tv_send.tv_usec, tv_recv.tv_sec, tv_recv.tv_usec,
																					tv_diff.tv_sec, tv_diff.tv_usec);
// Another way to do it
//	fprintf(trace_file, "temps en us: %ld us\n", ((tv_recv.tv_sec - tv_send.tv_sec) * 1000000 + tv_recv.tv_usec) - tv_send.tv_usec);
}



#endif /* SERVER_BLUEZ_5_43_RCM_HELP_FUNC_H_ */
