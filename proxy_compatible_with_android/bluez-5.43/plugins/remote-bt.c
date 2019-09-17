/*
 * Authors:
 * 	Natalya Rozhnova <natalya.rozhnova@nokia.com>
 * 	Marc-Olivier Buob <marc-olivier.buob@nokia.com>
 * Copyright (c) 2017 Nokia Bell Labs
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "src/plugin.h"

// Specific headers

#include <stdint.h>
#include <glib.h>
#include <stdlib.h>     // strtol
#include <string.h>     // memset
#include <ctype.h>      // isxdigit
#include <stdbool.h>    // bool
#include <sys/socket.h>

// For kernel sources
//#include "/usr/src/linux-headers-4.9.0-2-common/include/net/bluetooth/hci_core.h"
//#include "/usr/src/linux-headers-4.9.0-2-common/include/net/bluetooth/mgmt.h"
//#include "/usr/src/linux-headers-4.9.0-2-common/include/net/bluetooth/hci.h"
//#include <hci_core.h>
//#include <net/bluetooth/mgmt.h>
//#include <hci.h>


#include "bluetooth/bluetooth.h"    // needed by adapter.h
#include "bluetooth/sdp.h"          // needed by adapter.h

#include "lib/hci.h"
#include "lib/bluetooth.h"
#include "monitor/bt.h"

// to comment when adapter_static included
/*
#include "src/shared/mgmt.h"        // mgmt_register
#include "src/adapter.h"            // struct btd_adapter_driver
#include "lib/mgmt.h"               // MGMT_EV_DISCOVERING
#include "src/eir.h"
#include "src/shared/mgmt.h"
#include "src/device.h"
#include "src/log.h"
#include "src/shared/io.h"
*/

// When include this header, comment the above includes
#include "adapter_static.c"

// For kernel mgmt
//#define LE_LINK		0x80

// Copied from adapter.c, mgmt and io-mainloop
/*
struct io {
	int ref_count;
	int fd;
	uint32_t events;
	bool close_on_destroy;
	io_callback_func_t read_callback;
	io_destroy_func_t read_destroy;
	void *read_data;
	io_callback_func_t write_callback;
	io_destroy_func_t write_destroy;
	void *write_data;
	io_callback_func_t disconnect_callback;
	io_destroy_func_t disconnect_destroy;
	void *disconnect_data;
};
struct mgmt {
	int ref_count;
	int fd;
	bool close_on_unref;
	struct io *io;
	bool writer_active;
	struct queue *request_queue;
	struct queue *reply_queue;
	struct queue *pending_list;
	struct queue *notify_list;
	unsigned int next_request_id;
	unsigned int next_notify_id;
	bool need_notify_cleanup;
	bool in_notify;
	void *buf;
	uint16_t len;
	mgmt_debug_func_t debug_callback;
	mgmt_destroy_func_t debug_destroy;
	void *debug_data;
};
struct btd_adapter {
	int ref_count;

	uint16_t dev_id;
	struct mgmt *mgmt;

	bdaddr_t bdaddr;		 controller Bluetooth address
	uint32_t dev_class;		 controller class of device
	char *name;			 controller device name
	char *short_name;		 controller short name
	uint32_t supported_settings;	 controller supported settings
	uint32_t current_settings;	 current controller settings

	char *path;			 adapter object path
	uint8_t major_class;		 configured major class
	uint8_t minor_class;		 configured minor class
	char *system_name;		 configured system name
	char *modalias;			 device id (modalias)
	bool stored_discoverable;	 stored discoverable mode
	uint32_t discoverable_timeout;	 discoverable time(sec)
	uint32_t pairable_timeout;	 pairable time(sec)

	char *current_alias;		 current adapter name alias
	char *stored_alias;		 stored adapter name alias

	bool discovering;		 discovering property state
	bool filtered_discovery;	 we are doing filtered discovery
	bool no_scan_restart_delay;	 when this flag is set, restart scan
					 * without delay
	uint8_t discovery_type;		 current active discovery type
	uint8_t discovery_enable;	 discovery enabled/disabled
	bool discovery_suspended;	 discovery has been suspended
	GSList *discovery_list;		 list of discovery clients
	GSList *set_filter_list;	 list of clients that specified
					 * filter, but don't scan yet

	 current discovery filter, if any
	struct mgmt_cp_start_service_discovery *current_discovery_filter;

	GSList *discovery_found;	 list of found devices
	guint discovery_idle_timeout;	 timeout between discovery runs
	guint passive_scan_timeout;	 timeout between passive scans
	guint temp_devices_timeout;	 timeout for temporary devices

	guint pairable_timeout_id;	 pairable timeout id
	guint auth_idle_id;		 Pending authorization dequeue
	GQueue *auths;			 Ongoing and pending auths
	bool pincode_requested;		 PIN requested during last bonding
	GSList *connections;		 Connected devices
	GSList *devices;		 Devices structure pointers
	GSList *connect_list;		 Devices to connect when found
	struct btd_device *connect_le;	 LE device waiting to be connected
	sdp_list_t *services;		 Services associated to adapter

	struct btd_gatt_database *database;
	struct btd_advertising *adv_manager;

	gboolean initialized;

	GSList *pin_callbacks;
	GSList *msd_callbacks;

	GSList *drivers;
	GSList *profiles;

	struct oob_handler *oob_handler;

	unsigned int load_ltks_id;
	guint load_ltks_timeout;

	unsigned int confirm_name_id;
	guint confirm_name_timeout;

	unsigned int pair_device_id;
	guint pair_device_timeout;

	unsigned int db_id;		 Service event handler for GATT db

	bool is_default;		 true if adapter is default one
};
*/

// adapter.h
//
// struct btd_adapter_driver {
//     const char *name;
//     int (*probe) (struct btd_adapter *adapter);
//     void (*remove) (struct btd_adapter *adapter);
// };

static void to_eir_GSList_cb_write_uint128(gpointer item, gpointer pbuffer) {
    // TODO only write if the item is uint128_t

    // Read the string. Each consecutive pair of character corresponds to a byte.
    // bt_string2uuid(*(uuid_t **) pbuffer, item);
    uint128_t u128;
    char    * pc = (char *) item;
    uint8_t * pu = (uint8_t *) &u128;
    while (*pc) {
        // Convert the hexadecimal character (char c) into an hex digit (uint8_t n).
        uint8_t extracted, n = 0;
        for (extracted = 0; extracted < 2 && *pc; pc++) {
            char c = *pc;
            if (isdigit(c)) {
                if (c - '0') n += (c - '0') << (4 * (1 - extracted));
                extracted++;
            } else if (isalpha(c)) {
                if (c - '0') n += (tolower(c) - 'a' + 10) << (4 * (1 - extracted));
                extracted++;
            } // Other characters like '-' are ignored.
        }

        // Write n and move 1 byte forward.
        *pu++ = n;
    }

    // u128 is the big endian representation, so we now put the bytes in the right order.
    // http://stackoverflow.com/questions/8004790/how-to-change-byte-order-of-128-bit-number
    // We could also use *(uint32_t **) pbuffer (see bluetooth.h)
    *(*(uint32_t **) pbuffer)++ = ntohl(((uint32_t *) &u128)[3]);
    *(*(uint32_t **) pbuffer)++ = ntohl(((uint32_t *) &u128)[2]);
    *(*(uint32_t **) pbuffer)++ = ntohl(((uint32_t *) &u128)[1]);
    *(*(uint32_t **) pbuffer)++ = ntohl(((uint32_t *) &u128)[0]);

    // TODO: can we have heterogeneous services (uint16,32,128) in the same list?
    // I suspect that the answer is NO.
    // If we need to pass heterogeneous services, we just sort them by size, and make a list of services per uid size.
}

/*
void to_eir_uint16_write(gpointer item, gpointer pbuffer) {
    // In practice, item is a uint16_t *, pbuffer is an uint8_t **.
    printf("to_eir_uint16_write: begin: @ = %p\n", * (uint8_t **) pbuffer);
    size_t len = sizeof(uint8_t) + sizeof(uint32_t);    // The field contains the type, and the uint16_t.
    *(*(uint8_t **) pbuffer)++ = (uint8_t) len;         // Write size and move 1 byte forward.
    *(*(uint8_t **) pbuffer)++ = EIR_UUID16_SOME;       // Write type and move 1 byte forward.
    memcpy(*pbuffer, item, len);                        // Write value.
    *(uint8_t **) pbuffer += len;                       // Move len byte forward.
    printf("to_eir_uint16_write: end  : @ = %p\n", * (uint8_t **) pbuffer);
}
*/

static void to_eir_string_write(gpointer item, gpointer pbuffer) {
    // In practice, item is a char *, pbuffer is an uint8_t **.
    size_t len = strlen(item);                    // The field contains the type, the string null terminated.
    *(*(uint8_t **) pbuffer)++ = (uint8_t) len + 1;   // Write size and move 1 byte forward. Do not forget the type.
    *(*(uint8_t **) pbuffer)++ = EIR_NAME_SHORT;  // Write type and move 1 byte forward.
    memcpy(*(uint8_t **) pbuffer, item, len);     // Write the string and its ending '\0'.
    *(uint8_t **) pbuffer += len;                 // Move at the end of the string.
}

/**
 * Convert a eir_data structure into a an EIR, parsable by eir_parse.
 * @param eir_data The eir_data structure.
 * @param buffer The output buffer.
 * @param buffer_size The size of the buffer.
 *
 * Example 1: pre-allocated buffer (eventually reallocated if too small)/
 *
 * char buffer[100];
 * size_t size;
 * to_eir(eir_data, &buffer, &size);
 *
 * Example 2: unallocated buffer.
 * size_t size;
 * char * buffer = NULL;
 * to_eir(eir_data, &buffer, &size);
 * free(buffer);
 */

static gpointer to_eir(const struct eir_data * eir_data,
					   gpointer buffer, uint16_t *pbuffer_size)
{
    uint16_t eir_size = 0;      // type imposed by mgmt_ev_device_found
    gpointer ret = buffer;
    uint8_t num_services = 0;

    // Pre-requisites:
    //
    // An EIR is made of a sequence of fields.
    //
    // Each field is made as follow:
    // - 1 byte for the size s (uint8_t)
    // - 1 byte for the type   (uint8_t)
    // - (s-1) bytes for the data. Indeed s = data_len + sizeof(size) = data_len + 1
    //
    // If a field start at @, the next field start at @ + s + 1 (because we did not count the type in s).
    //
    // Knowing the length of the whole EIR is sufficient to deduce when to stop to read the EIR buffer.
    // Its ends should match the end of the last field.
    // The order in which the fields appear seems to be irrelevant.
    // Indeed, the type suffices to identify which part of eir_data must be set.
    //
    // Approach:
    //
    // 1) Pass over eir_data to determine the size of the field we have to write.
    // 2) Allocate the buffer to build the EIR.
    // 3) Write the buffer.

    // 1) Determine the size to allocate.
    // For each member of the eir_data structure, we allocated the adequate number of bytes.

    if (eir_data->name) {
        eir_size += 2;                      // size, type
        eir_size += strlen(eir_data->name); // value
    }

    if (eir_data->services) {
        num_services = (uint8_t) g_slist_length(eir_data->services);
        eir_size += 2;                      // size, type
        eir_size += num_services * 128/8;   // values
    }

    // 2) Allocation
    // Now we can allocate/reallocate the buffer to write the EIR into it.

    if (buffer) {
        printf("pre allocated buffer\n");
        if (eir_size > *pbuffer_size) {
            printf("enlarge buffer %zu > %zu\n", eir_size, *pbuffer_size);
            // Enlarge my buffer.
            ret = buffer = realloc(buffer, eir_size);
            *pbuffer_size = eir_size;
        }
    } else {
        // Allocate the buffer
        ret = buffer = malloc(eir_size);
        if (!buffer) {
            return NULL; // Not enough memory
        }
        *pbuffer_size = eir_size;
    }

    // 3) Second pass: write into the buffer the EIR.

    if (eir_data->name) {
        const uint8_t *begin_field = buffer; // DEBUG
        to_eir_string_write(eir_data->name, &buffer);
    }

    if (eir_data->services) {
        const uint8_t *begin_field = buffer; // DEBUG
        // TODO: I assume that we only have services of 128 bits. In pratice I think we should
        // make a list of services of 16 bits, another one of 32 bits, and a last one of 128 bits.
        // Each groups leads to a list. Under my hypothesis I only have one list to write.

        // byte0: size of the array (in bytes)
        // byte1: type of the cell
        printf("num_services = %zu\n", (size_t) num_services);
        *(uint8_t *) buffer++ = num_services * 128/8 + 1; // Size: 128 bits per services + 1 byte for the type.
        *(uint8_t *) buffer++ = EIR_UUID128_ALL;          // Type: our cell is an uint128_t

        // next bytes: the uint128_t value(s)
        g_slist_foreach(eir_data->services, to_eir_GSList_cb_write_uint128, &buffer);

        // to use bt_uuid2string, we have to prepare a struct uuid_t (see src/uuid-helper.c)
        printf("s:%d t:%d v:'%p'\n", begin_field[0], begin_field[1], begin_field+2); // DEBUG
    }

    return ret;
}

void print_iterator(gpointer item, gpointer prefix) {
     printf("%s %s\n", (const char*) prefix, (const char *) item);
}

static void discovery_started_callback(uint16_t index,
									   uint16_t length,
									   const void *param,
									   void *user_data)
{
	//struct btd_device *dev;
    const struct mgmt_ev_discovering *ev = param;
    struct btd_adapter *adapter = user_data;
    const char *addr_str = "C4:D9:87:C3:30:E3";
    bdaddr_t addr;
    struct eir_data eir_data;
    int len = 0;
    GSList *l;
    int i = 1;
    //uint8_t uuid[4] = {0xE5, 0xFF, 0x00, 0x00};

    // PLOP
    memset(&eir_data, 0, sizeof(eir_data));

    str2ba(addr_str, &addr);
    DBG("NATALYA CALLBACK hci%u type %u discovering %u method %d", adapter->dev_id, ev->type, ev->discovering, adapter->filtered_discovery);

    // Initialize and write name
    g_free(eir_data.name);
    eir_data.name = "Natalya-FAKE-LED";
    //eir_data.services = g_slist_append(eir_data.services, "0000ffe5");
    eir_data.services = g_slist_append(eir_data.services, "0000ffe5-0000-1000-8000-00805f9b34fb");

#ifdef NATALYA
    // 0000ffe5-0000-1000-8000-00805f9b34fb
    uint8_t uuid[16] = {
        0xfb, 0x34, 0x9b, 0x5f,
        0x80, 0x00, 0x00, 0x80,
        0x00, 0x10, 0x00, 0x00,
        0xe5, 0xff, 0x00, 0x00
    };

    // Convert to EIR
    uint8_t data[80];
    data[0] = strlen(eir_data.name) + 1;
    data[1] = EIR_NAME_SHORT;
    memcpy(&data[2], eir_data.name, strlen(eir_data.name) * sizeof(char));
    len = strlen(eir_data.name) + 2;
    //    data[len] = g_slist_length(eir_data.services) * 4 + 1;
    //    data[len + 1] = EIR_UUID32_ALL;
    data[len] = g_slist_length(eir_data.services) * sizeof(uuid) + 1;
    data[len + 1] = EIR_UUID128_ALL;

    for (l = eir_data.services; l != NULL; l = g_slist_next(l)) {
        memcpy(&data[len + 1 + i], uuid, sizeof(uuid));
        i += sizeof(uuid);
    }
    uint16_t eir_len = 80;
#else

    // Convert to EIR
    uint8_t * eir = NULL;
    uint16_t eir_len = 0;
    uint8_t * data = to_eir(&eir_data, eir, &eir_len);
    printf("NATALYA: eir     = %p\n", data);
    printf("NATALYA: eir_len = %zu\n", (size_t) eir_len);
#endif

    // Display
/*    for (uint8_t i = 0; i < eir_len ; i++) {
        printf("NATALYA CALLBACK DATA [%02d] %02X %c\n", i, data[i], data[i]);
    }*/
    update_found_devices(adapter,
            &addr,
            BDADDR_LE_PUBLIC, -55,
            false, true,
            false, data,
            eir_len);
//    send_event(adapter->mgmt->io->fd, MGMT_EV_DEVICE_FOUND, eir, sizeof(eir));
    DBG("NATALYA CALLBACK3 hci%u type %u discovering %u method %d", adapter->dev_id, ev->type,
            ev->discovering, adapter->filtered_discovery);
}
//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
/*static void test_callback(uint16_t index,
						 uint16_t length,
						 const void *param,
						 void *user_data)
{
	DBG("NATALYA DBG: INSIDE THE CALLBACK!!!!!!!!!!!!!!!!!");
}

static void test_sending(uint16_t index,
						 uint16_t length,
						 const void *param,
						 void *user_data)
{
	//-----------------EIR---------------------------
	//struct btd_device *dev;
    const struct mgmt_ev_discovering *ev = param;
    struct btd_adapter *adapter = user_data;
    const char *addr_str = "C4:D9:87:C3:30:E3";
    bdaddr_t addr;
    struct eir_data eir_data;
    int len = 0;
    GSList *l;
    int i = 1;
    //uint8_t uuid[4] = {0xE5, 0xFF, 0x00, 0x00};

    // PLOP
    memset(&eir_data, 0, sizeof(eir_data));

    str2ba(addr_str, &addr);
    DBG("NATALYA CALLBACK hci%u type %u discovering %u method %d", adapter->dev_id, ev->type, ev->discovering, adapter->filtered_discovery);

    // Initialize and write name
    g_free(eir_data.name);
    eir_data.name = "Natalya-FAKE-LED";
    //eir_data.services = g_slist_append(eir_data.services, "0000ffe5");
    eir_data.services = g_slist_append(eir_data.services, "0000ffe5-0000-1000-8000-00805f9b34fb");

    // Convert to EIR
        uint8_t * eir = NULL;
        uint16_t eir_len = 0;
        uint8_t * data = to_eir(&eir_data, eir, &eir_len);
        printf("NATALYA: eir     = %p\n", data);
        printf("NATALYA: eir_len = %zu\n", (size_t) eir_len);
    //----------------------------------------------

	mgmt_register(adapter->mgmt, MGMT_EV_DEVICE_FOUND,
	            adapter->dev_id,
				test_callback,
	//            discovery_started_callback,
	            adapter, NULL);


	 * 	void mgmt_device_found(struct hci_dev *hdev, bdaddr_t *bdaddr, u8 link_type,
				       u8 addr_type, u8 *dev_class, s8 rssi, u32 flags,
				       u8 *eir, u16 eir_len, u8 *scan_rsp, u8 scan_rsp_len);

		struct discovery_state *d = &hdev->discovery;

			mgmt_device_found(hdev, &d->last_adv_addr, LE_LINK,
					  d->last_adv_addr_type, NULL,
					  d->last_adv_rssi, d->last_adv_flags,
					  d->last_adv_data,
					  d->last_adv_data_len, NULL, 0);

	mgmt_device_found(hci_dev_get(adapter->dev_id), addr, LE_LINK,
					  BDADDR_LE_PUBLIC, NULL, -55, false,
				       data, eir_len, NULL, 0);

//	send_event(adapter->mgmt->io ,adapter->mgmt->io->fd, MGMT_EV_DEVICE_FOUND, &ev_fake_device, ev_fake_device_len);
}*/
//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

unsigned int id = 0;
static int remote_bt_probe(struct btd_adapter *adapter)
{
    id = mgmt_register(adapter->mgmt, MGMT_EV_DISCOVERING,
            adapter->dev_id,
//			test_sending,
            discovery_started_callback,
            adapter, NULL);

    // This id must be save for remote_bt_remove
    DBG("MARCO: adapter = %p id = %d", adapter, id);
    char buffer[100];
    ba2str(&adapter->bdaddr, buffer);
    DBG("MARCO: dev_id = %d btaddr = %s", adapter->dev_id, buffer);
	return 0;
}

static void remote_bt_remove(struct btd_adapter *adapter) {
    // TODO:
    // bool mgmt_unregister(struct mgmt *mgmt, unsigned int id);

    DBG("remote_bt_remove %p", adapter);
    mgmt_unregister(adapter->mgmt, id);
}

static struct btd_adapter_driver remote_bt_driver = {
	.name	= "Remote Bluetooth",
	.probe	= remote_bt_probe,
	.remove	= remote_bt_remove,
};

static int remote_bt_init(void) {
    DBG("MARCO: INIT: remote_bt_init");
	return btd_register_adapter_driver(&remote_bt_driver);
}

static void remote_bt_exit(void) {
	DBG("MARCO: EXIT: remote_bt_exit");
	btd_unregister_adapter_driver(&remote_bt_driver);
}

BLUETOOTH_PLUGIN_DEFINE(remote_bt, VERSION,
		BLUETOOTH_PLUGIN_PRIORITY_LOW, remote_bt_init, remote_bt_exit)
