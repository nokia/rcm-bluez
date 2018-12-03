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
	Marc-Olivier Buob <marc-olivier.buob@nokia-bell-labs.com>
	Hui YIN <phoebe_yin@msn.com>
*/

#include "attrib/gattrib.h"
#include "src/shared/mgmt.h"        // mgmt_register
#include "src/adapter.h"            // struct btd_adapter_driver
#include "lib/mgmt.h"               // MGMT_EV_DISCOVERING
#include "src/eir.h"
#include "src/shared/mgmt.h"
#include "src/device.h"
#include "src/log.h"

struct btd_adapter {
	int ref_count;

	uint16_t dev_id;
	struct mgmt *mgmt;

	bdaddr_t bdaddr;		/* controller Bluetooth address */
	uint32_t dev_class;		/* controller class of device */
	char *name;			/* controller device name */
	char *short_name;		/* controller short name */
	uint32_t supported_settings;	/* controller supported settings */
	uint32_t current_settings;	/* current controller settings */

	char *path;			/* adapter object path */
	uint8_t major_class;		/* configured major class */
	uint8_t minor_class;		/* configured minor class */
	char *system_name;		/* configured system name */
	char *modalias;			/* device id (modalias) */
	bool stored_discoverable;	/* stored discoverable mode */
	uint32_t discoverable_timeout;	/* discoverable time(sec) */
	uint32_t pairable_timeout;	/* pairable time(sec) */

	char *current_alias;		/* current adapter name alias */
	char *stored_alias;		/* stored adapter name alias */

	bool discovering;		/* discovering property state */
	bool filtered_discovery;	/* we are doing filtered discovery */
	bool no_scan_restart_delay;	/* when this flag is set, restart scan
					 * without delay */
	uint8_t discovery_type;		/* current active discovery type */
	uint8_t discovery_enable;	/* discovery enabled/disabled */
	bool discovery_suspended;	/* discovery has been suspended */
	GSList *discovery_list;		/* list of discovery clients */
	GSList *set_filter_list;	/* list of clients that specified
					 * filter, but don't scan yet
					 */
	/* current discovery filter, if any */
	struct mgmt_cp_start_service_discovery *current_discovery_filter;

	GSList *discovery_found;	/* list of found devices */
	guint discovery_idle_timeout;	/* timeout between discovery runs */
	guint passive_scan_timeout;	/* timeout between passive scans */
	guint temp_devices_timeout;	/* timeout for temporary devices */

	guint pairable_timeout_id;	/* pairable timeout id */
	guint auth_idle_id;		/* Pending authorization dequeue */
	GQueue *auths;			/* Ongoing and pending auths */
	bool pincode_requested;		/* PIN requested during last bonding */
	GSList *connections;		/* Connected devices */
	GSList *devices;		/* Devices structure pointers */
	GSList *connect_list;		/* Devices to connect when found */
	struct btd_device *connect_le;	/* LE device waiting to be connected */
	sdp_list_t *services;		/* Services associated to adapter */

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

	unsigned int db_id;		/* Service event handler for GATT db */

	bool is_default;		/* true if adapter is default one */
};

/* Per-bearer (LE or BR/EDR) device state */
struct bearer_state {
	bool paired;
	bool bonded;
	bool connected;
	bool svc_resolved;
};

struct csrk_info {
	uint8_t key[16];
	uint32_t counter;
};

struct btd_device {
	int ref_count;

	bdaddr_t	bdaddr;
	uint8_t		bdaddr_type;
	char		*path;
	bool		bredr;
	bool		le;
	bool		pending_paired;		/* "Paired" waiting for SDP */
	bool		svc_refreshed;
	GSList		*svc_callbacks;
	GSList		*eir_uuids;
	struct bt_ad	*ad;
	uint8_t         ad_flags[1];
	char		name[MAX_NAME_LENGTH + 1];
	char		*alias;
	uint32_t	class;
	uint16_t	vendor_src;
	uint16_t	vendor;
	uint16_t	product;
	uint16_t	version;
	uint16_t	appearance;
	char		*modalias;
	struct btd_adapter	*adapter;
	GSList		*uuids;
	GSList		*primaries;		/* List of primary services */
	GSList		*services;		/* List of btd_service */
	GSList		*pending;		/* Pending services */
	GSList		*watches;		/* List of disconnect_data */
	bool		temporary;
	guint		disconn_timer;
	guint		discov_timer;
	struct browse_req *browse;		/* service discover request */
	struct bonding_req *bonding;
	struct authentication_req *authr;	/* authentication request */
	GSList		*disconnects;		/* disconnects message */
	DBusMessage	*connect;		/* connect message */
	DBusMessage	*disconnect;		/* disconnect message */
	GAttrib		*attrib;

	struct bt_att *att;			/* The new ATT transport */
	uint16_t att_mtu;			/* The ATT MTU */
	unsigned int att_disconn_id;

	/*
	 * TODO: For now, device creates and owns the client-role gatt_db, but
	 * this needs to be persisted in a more central place so that proper
	 * attribute cache support can be built.
	 */
	struct gatt_db *db;			/* GATT db cache */
	struct bt_gatt_client *client;		/* GATT client instance */
	struct bt_gatt_server *server;		/* GATT server instance */

	struct btd_gatt_client *client_dbus;

	struct bearer_state bredr_state;
	struct bearer_state le_state;

	struct csrk_info *local_csrk;
	struct csrk_info *remote_csrk;

	sdp_list_t	*tmp_records;

	time_t		bredr_seen;
	time_t		le_seen;

	gboolean	trusted;
	gboolean	blocked;
	gboolean	auto_connect;
	gboolean	disable_auto_connect;
	gboolean	general_connect;

	bool		legacy;
	int8_t		rssi;
	int8_t		tx_power;

	GIOChannel	*att_io;
	guint		store_id;

	// Natalya's modification
	// This value is used especially during the connect procedure to a given device
	// When an Application asks to launch a connection procedure, the corresponding adapter is solicitated
	// and btio loop is created to listen for signaling. The problem is that in our case where the device is discovered remotely,
	// the physical connection through physical dongle will return fail because this device doesn't exist in proximity.
	// To avoid this, we should check at the beginning of the procedure whether a given device has been discovered remotely.
 	bool		remote;
 	connect_cb_t connect_callback;
};

struct discovery_filter {
	uint8_t type;
	uint16_t pathloss;
	int16_t rssi;
	GSList *uuids;
};
