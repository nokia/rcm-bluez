#define LOG_TAG "rcm_client"

#include "rcm_client.h"
#include "btif_api.h"
#include "osi/include/log.h"
#include "osi/include/list.h"
#include "osi/include/osi.h"
#include "bta/dm/bta_dm_int.h"
#include "bta/include/bta_api.h"		 		 // BTA_DM_INQ_RES_EVT && tBTA_DM_SEARCH && tBTA_DM_INQ_RES
#include "stack/include/bt_types.h"				 // BLE_ADDR_PUBLIC
#include "stack/include/btm_api_types.h" 		 // BTM_INQ_RESULT_BLE
#include "stack/include/btm_ble_api_types.h"	 // BTM_BLE_SCAN_RSP_EVT
//#include "stack/include/gatt_api.h"
#include "stack/btm/btm_ble_int.h"
#include "stack/btm/btm_int_types.h"
#include "stack/btm/btm_int.h"
#include "bta/gatt/bta_gattc_int.h"
//#include "types/raw_address.h"
#include "bta/dm/bta_dm_int.h"					 // tBTA_DM_SEARCH_CB bta_dm_search_cb
//#include "osi/include/config.h"
#include "btif_common.h"
#include "btif_storage.h"
#include "btif_util.h"
//#include "btu.h"
//#include "mca_api.h"

#include <sys/socket.h>
#include <sys/select.h>
#include <signal.h>
#include <pthread.h>

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>

/*
#include <base/logging.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
*/

#ifndef BTE_RCM_CONF_FILE
#if defined(OS_GENERIC)
#define BTE_RCM_CONF_FILE "bt_rcm_proxies.conf"
#else  // !defined(OS_GENERIC)
#define BTE_RCM_CONF_FILE "/etc/bluetooth/bt_rcm_proxies.conf"
#endif  // defined(OS_GENERIC)
#endif  // BTE_RCM_CONF_FILE

#define REMOTE_CMD_FAIL							0x00
#define REMOTE_CMD_START_DISCOVERY              0x01
#define REMOTE_CMD_CONNECT_DEVICE				0x02
#define REMOTE_CMD_STOP_DISCOVERY				0x03
#define REMOTE_CMD_CACHE_INFO					0x04
#define REMOTE_CMD_RELEASE						0x05
#define REMOTE_CHAR_WRITE						0x06
#define REMOTE_CMD_SET_FILTER                   0X07
#define REMOTE_CMD_DISCONNECT_DEVICE			0x08
#define REMOTE_CMD_GET_MAC						0x09
#define REMOTE_DESC_WRITE						0x0A
#define REMOTE_START_STOP_NOTIF					0x0B

#define REPLY_HEADER_SIZE								1

static bool initialized = false;
static proxy_t rcm_proxy;
static int id = 1;
static bool start_discovery_in_progress = false;
//static bool connection_in_progress = false;
//static bool connected = false;

static pthread_t rcm_select_thread_id = -1;

static int rcm_send_to_proxy(proxy_t *proxy);
bool rcm_get_initialized();
remote_device_t * rcm_get_device(list_rcm_devices_t *list, const RawAddress& addr);
bool rcm_get_connection_in_progress(list_rcm_devices_t *list);

//tBTA_GATTC_CLCB* conn_in_progress_for_app = NULL;
tGATT_VALUE *write_in_progress = NULL;
bool registered_for_notifications = false;

// -------------------------------------------------------------------------
bool rcm_registered_for_notif(){
	return registered_for_notifications;
}

void rcm_register_for_notif(bool val){
	LOG_DEBUG(LOG_TAG, "%s registered = %d", __func__, val);
	registered_for_notifications = val;
}

bool rcm_connection_in_progress(const RawAddress &bdaddr){
	LOG_DEBUG(LOG_TAG, "%s", __func__);
	if(bdaddr.IsEmpty()){
		return rcm_get_connection_in_progress(rcm_proxy.proxy_devices);
	}

	remote_device_t *rdev = rcm_get_device(rcm_proxy.proxy_devices, bdaddr);
	if(rdev != NULL){
		return rdev->connection_in_progress;
	}
	return false;
}

bool rcm_connected(const RawAddress &bdaddr){
	remote_device_t *rdev = rcm_get_device(rcm_proxy.proxy_devices, bdaddr);
	if(rdev != NULL){
		return rdev->connected;
	}
	return false;
}

int rcm_rawaddr_to_str(const RawAddress& ba, char *str)
{
	return sprintf(str, "%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X",
		ba.address[0], ba.address[1], ba.address[2], ba.address[3], ba.address[4], ba.address[5]);
}

void rcm_print_raw_bda(const RawAddress& ba){
	LOG_INFO(LOG_TAG, "%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X", ba.address[0], ba.address[1], ba.address[2], ba.address[3], ba.address[4], ba.address[5]);
}

void rcm_get_client_mac_address( unsigned char *mac_address)
{
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1)
	{ /* handle error*/ };

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { /* handle error */ }
    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) {
		strcpy(ifr.ifr_name, it->ifr_name);
		if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
			if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
			if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
					success = 1;
				break;
				}
			}
		}else
		{ /* handle error */ }
    }

//    unsigned char mac_address[6];
    if (success) {
    	memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);
    }

    for (int i = 0; i < 6; ++i)
    	LOG_DEBUG(LOG_TAG, "%02x:", mac_address[i]);
}

data_t *rcm_create_data_pkt(uint8_t *data, size_t len) {
	data_t *item = (data_t *)malloc(sizeof(data_t));
	item->data = (uint8_t *)malloc(len);
	memcpy(item->data, data, len);
	item->data_len = len;

	return item;
}

void rcm_clear_data_pkt(data_t *item) {
	if(!item)
		return;
	if(item->data) {
		LOG_DEBUG(LOG_TAG, "%s Cleaning", __func__);
		free(item->data);
 	}
	free(item);
}

void rcm_print_msg_hex(ssize_t num_recv, uint8_t *server_reply)
{
	LOG_INFO(LOG_TAG, "Got %zu bytes\n", num_recv);
	ssize_t i;

	// Hex
	for (i = 0; i < num_recv; ++i) {
		LOG_INFO(LOG_TAG, "%02x ", server_reply[i]);
	}
}
// -------------------------------------------------------------------------
// list -------------------------------------------------------------------------
// This list contains the bt addresses of the devices remotely reachable through the RCM proxy.

list_rcm_devices_t * rcm_create_device_list(){
	return (list_rcm_devices_t *) calloc(1, sizeof(list_rcm_devices_t));
}

void rcm_delete_device_list(list_rcm_devices_t *list){
	remote_device_t * next = NULL;
	for (remote_device_t * cur = list->head; cur; cur = next) {
		next = cur->next;
		free(cur);
	}
	free(list);
}

void rcm_push_device(list_rcm_devices_t *list, RawAddress bdaddr){
	remote_device_t *dev = (remote_device_t*) malloc(sizeof(remote_device_t));

	dev->bdaddr = bdaddr;
	dev->connection_in_progress = false;
	dev->connected = false;
	dev->conn_in_progress_for_app = NULL;
	dev->next = list->head;
	list->head = dev;
	list->size++;
}

int rcm_get_list_size(list_rcm_devices_t *list){
	return list->size;
}

bool rcm_find_device(list_rcm_devices_t *list, const RawAddress& addr){
	remote_device_t *current = list->head;
	while(current){
		if(current->bdaddr == addr)
			return true;
		current = current->next;
	}
	return false;
}

remote_device_t * rcm_get_device(list_rcm_devices_t *list, const RawAddress& addr){
	remote_device_t *current = list->head;
	while(current){
		if(current->bdaddr == addr)
			return current;
		current = current->next;
	}
	return NULL;
}

bool rcm_get_connection_in_progress(list_rcm_devices_t *list){
	remote_device_t *current = list->head;
	while(current){
		if(current->connection_in_progress)
			return true;
		current = current->next;
	}
	return false;
}

// data queue --------------------------------------------------------------
data_queue_t* rcm_create_data_queue(proxy_t *proxy) {
	proxy->rcm_send_queue = (data_queue_t*) malloc(sizeof(data_queue_t));
	if(!proxy->rcm_send_queue)
		return NULL;
//	queue->capacity = RCM_QUEUE_CAPACITY;
	proxy->rcm_send_queue->front = proxy->rcm_send_queue->size = 0;
	proxy->rcm_send_queue->rear = RCM_QUEUE_CAPACITY - 1; // This is important, see the enqueue
	proxy->rcm_send_queue->array = (data_t**)malloc(RCM_QUEUE_CAPACITY * sizeof(data_t *));
	if(! proxy->rcm_send_queue->array) {
		free(proxy->rcm_send_queue);
		proxy->rcm_send_queue = NULL;
	}
	return proxy->rcm_send_queue;
}

void rcm_delete_data_queue(data_queue_t *queue) {
	for(size_t i = 0; i < RCM_QUEUE_CAPACITY; i++){
		if(queue->array[i]) {
			LOG_DEBUG(LOG_TAG,"Cleaning %s\n", queue->array[i]->data);
			free(queue->array[i]);
		}
	}
	free(queue->array);
	free(queue);
}

bool rcm_queue_is_full(data_queue_t* queue) {
	return (queue->size == RCM_QUEUE_CAPACITY);
}

// Queue is empty when size is 0
bool rcm_queue_is_empty(data_queue_t* queue) {
	return (queue->size == 0);
}

bool rcm_queue_enqueue(data_queue_t* queue, data_t *item)
{
	if (rcm_queue_is_full(queue))
		return false;
	queue->rear = (queue->rear + 1)%RCM_QUEUE_CAPACITY;
	queue->array[queue->rear] = item;
	queue->size = queue->size + 1;
	LOG_DEBUG(LOG_TAG,"Packet of length = %d enqueued to queue, size = %d\n", (int)item->data_len, queue->size);
	return true;
}

data_t * rcm_queue_dequeue(data_queue_t* queue)
{
	if (rcm_queue_is_empty(queue))
		return NULL;
	data_t * item = queue->array[queue->front];
	queue->array[queue->front] = NULL;
	queue->front = (queue->front + 1)%RCM_QUEUE_CAPACITY;
	queue->size = queue->size - 1;
	LOG_DEBUG(LOG_TAG,"Packet of length = %d dequeued from queue, size = %d\n", (int)item->data_len, queue->size);

	return item;
}

data_t * rcm_queue_front(data_queue_t* queue)
{
	if (rcm_queue_is_empty(queue))
		return NULL;
	return queue->array[queue->front];
}

data_t * rcm_queue_rear(data_queue_t* queue)
{
	if (rcm_queue_is_empty(queue))
		return NULL;
	return queue->array[queue->rear];
}

// proxy -----------------------------------------------------------------------

static void rcm_delete_proxy(proxy_t *proxy)
{
  close(proxy->socket);
  rcm_delete_data_queue(proxy->rcm_send_queue);
  rcm_delete_device_list(proxy->proxy_devices);
}

static int rcm_create_proxy(proxy_t *proxy)
{
  data_queue_t *q = rcm_create_data_queue(proxy);
  if(!q)
	  LOG_ERROR(LOG_TAG, "%s Failed to create queue", __func__);

  proxy->proxy_devices = rcm_create_device_list();
  return 0;
}

static char *rcm_proxy_get_address_str(proxy_t *proxy)
{
  static char ret[INET_ADDRSTRLEN + 10];
  char proxy_ipv4_str[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &proxy->address.sin_addr, proxy_ipv4_str, INET_ADDRSTRLEN);
  sprintf(ret, "%s:%d", proxy_ipv4_str, proxy->address.sin_port);

  return ret;
}
// ---------------------------------------------------------------------------------
static void rcm_send_packet( proxy_t 	*proxy,
							 uint8_t	*packet_to_send,
							 size_t		 packet_size) {
	LOG_DEBUG(LOG_TAG, "%s proxy = %s", __func__, rcm_proxy_get_address_str(proxy));

	if(!rcm_get_initialized()){
		LOG_ERROR(LOG_TAG, "%s RCM is not initialized, ignore all requests to proxy", __func__);
		return;
	}

	unsigned char mac_address[6];
	rcm_get_client_mac_address(mac_address);

	for (int i = 0; i < 6; ++i)
    	LOG_DEBUG(LOG_TAG, "%02x:", mac_address[i]);

	uint8_t *message = (uint8_t *)malloc(packet_size + 6 + 1);
	size_t length = 0;

	message[length] = 6 + packet_size + 1;
	length += 1;

	memcpy(&message[length], mac_address, 6);
	length += 6;

	memcpy(&message[length], packet_to_send, packet_size);
	length += packet_size;

	data_t *pkt = rcm_create_data_pkt(message, length);
	bool ok = rcm_queue_enqueue(proxy->rcm_send_queue, pkt);

	// wakeup select loop if the queue was empty until now
	if(ok && proxy->rcm_send_queue->size == 1)
		rcm_send_to_proxy(proxy);

	free(packet_to_send);
}
// On REMOTE_CMD_GET_MAC command reception
static void rcm_send_mac_address(proxy_t *proxy)
{
	if(!rcm_get_initialized()){
		LOG_ERROR(LOG_TAG, "%s RCM is not initialized, ignore all requests to proxy", __func__);
		return;
	}

	uint8_t *message = (uint8_t *)malloc(1 + 1);
	size_t length = 0;

	// [appid_len][app_id][cmd]:
	// appid_len = 0, app_id not filed, cmd = REMOTE_CMD_GET_MAC
	message[length] = 0;
	length += 1;

	message[length] = (uint8_t) REMOTE_CMD_GET_MAC;
	length += 1;

	rcm_send_packet (proxy, message, length);
}

void get_id(char *str){
	LOG_INFO(LOG_TAG, "%s", __func__);

	sprintf(str, "android%d", id);

//	id++;
}

// Stop discovery
static void rcm_stop_remote_scan(){
	LOG_INFO(LOG_TAG, "%s", __func__);

	if(!rcm_get_initialized()){
		LOG_ERROR(LOG_TAG, "%s RCM is not initialized, ignore all requests to proxy", __func__);
		return;
	}
	//	if (!start_discovery_in_progress)
	//		return;
	// start_discovery_in_progress = false;
	char app_id[10] = {0};
	get_id(app_id);
	uint8_t appid_len = strlen(app_id);
	LOG_DEBUG(LOG_TAG, "%s id = %s", __func__, app_id);

	uint8_t *message = (uint8_t *)malloc(1 + appid_len + 1);
	size_t length = 0;

	//[appid_len][app_id][cmd]
	message[length] = appid_len;
	length += 1;

	memcpy(&message[length], app_id, appid_len);
	length += appid_len;

	message[length] = (uint8_t) REMOTE_CMD_STOP_DISCOVERY;
	length += 1;

	rcm_send_packet(&rcm_proxy, message, length);
}

// Start discovery callback
static void rcm_start_remote_scan(bool start) {
	LOG_INFO(LOG_TAG, "%s Start discovery callback is called! started? %d", __func__, start_discovery_in_progress);
// Uncomment it when stop discovery is implemented, otherwise it will block the future calls for start_discovery
//	if (start_discovery_in_progress)
//		return;
//	start_discovery_in_progress = true;
	if(!rcm_get_initialized()){
		LOG_ERROR(LOG_TAG, "%s RCM is not initialized, ignore all requests to proxy", __func__);
		return;
	}

	if(!start){
		rcm_stop_remote_scan();
		return;
	}

	char app_id[10] = {0};
	get_id(app_id);
	uint8_t appid_len = strlen(app_id);
	LOG_DEBUG(LOG_TAG, "%s id = %s", __func__, app_id);

	uint8_t *message = (uint8_t *) malloc(1 + appid_len + 1);
	size_t length = 0;

	//[appid_len][app_id][cmd]
	message[length] = appid_len;
	length += 1;

	memcpy(&message[length], app_id, appid_len);
	length += appid_len;

	message[length] = (uint8_t) REMOTE_CMD_START_DISCOVERY;
	length += 1;

	rcm_send_packet(&rcm_proxy, message, length);
}

static void rcm_provide_discovery_results(uint8_t *addr, uint8_t addr_type, uint8_t* p_eir, size_t eir_len) {

	LOG_DEBUG(LOG_TAG, "%s", __func__);
	// Note that the addr_type received from bluez is different that the one used by fluoride.
	// We can't use it as it is. The difference should be bluez_addr_type = fluoride_addr_type + 1

	RawAddress bdaddr = RawAddress((uint8_t (&)[6])addr[0]);
	bool dev_exists = rcm_find_device(rcm_proxy.proxy_devices, bdaddr);
	if(!dev_exists)
		rcm_push_device(rcm_proxy.proxy_devices, bdaddr);

	tBTA_DM_SEARCH result;

	result.inq_res.bd_addr = bdaddr;
	result.inq_res.rssi = BTM_INQ_RES_IGNORE_RSSI;
	result.inq_res.ble_addr_type = BLE_ADDR_PUBLIC;
	result.inq_res.inq_result_type = BTM_INQ_RESULT_BLE;
	result.inq_res.device_type = BT_DEVICE_TYPE_BLE;
	result.inq_res.flag = 0;
	result.inq_res.ble_evt_type = 27;//BTM_BLE_SCAN_RSP_EVT; // ???
	result.inq_res.ble_primary_phy = 1;
	result.inq_res.ble_secondary_phy = 0;
	result.inq_res.ble_advertising_sid = 255;
	result.inq_res.ble_tx_power = 127;
	result.inq_res.ble_periodic_adv_int = 0;

	/* application will parse EIR to find out remote device name */
	result.inq_res.p_eir = p_eir;
	result.inq_res.eir_len = (uint16_t)eir_len;

	tINQ_DB_ENT* p_i = btm_inq_db_find(bdaddr);

	if (p_i == NULL)
		p_i = btm_inq_db_new(bdaddr);

	tBTM_INQ_RESULTS* p_cur = &p_i->inq_info.results;
	p_cur->ble_addr_type = result.inq_res.ble_addr_type;
	p_cur->ble_advertising_sid = result.inq_res.ble_advertising_sid;
	p_cur->ble_evt_type = result.inq_res.ble_evt_type;
	p_cur->ble_periodic_adv_int = result.inq_res.ble_periodic_adv_int;
	p_cur->ble_primary_phy = result.inq_res.ble_primary_phy;
	p_cur->ble_secondary_phy = result.inq_res.ble_secondary_phy;
	p_cur->ble_tx_power = result.inq_res.ble_tx_power;
	p_cur->device_type = result.inq_res.device_type;
	p_cur->inq_result_type = result.inq_res.inq_result_type;
	p_cur->remote_bd_addr = result.inq_res.bd_addr;
	p_cur->rssi = result.inq_res.rssi;

	// Check the InqDb
	tBTM_INQ_INFO *p_inq_info = BTM_InqDbRead(bdaddr);
	LOG_DEBUG(LOG_TAG, "%s checking InqDb: device_type = %02x", __func__, p_inq_info->results.device_type);

	if (p_inq_info != NULL) {
		result.inq_res.remt_name_not_required = false;
	}
	if (result.inq_res.remt_name_not_required){
		p_inq_info->appl_knows_rem_name = true;
	}

	/*   p_i = btm_inq_db_new(bdaddr); // from btm_ble_gap.cc: btm_ble_process_adv_pkt_cont(...)
  p_inq_info = BTM_InqDbRead(p_inq->remote_bd_addr);
  if (p_inq_info != NULL) {
    result.inq_res.remt_name_not_required = false;
  }
	 */
	if (bta_dm_search_cb.p_scan_cback)
		bta_dm_search_cb.p_scan_cback(BTA_DM_INQ_RES_EVT, &result);
	//
	//  if (p_inq_info) {
	/* application indicates if it knows the remote name, inside the callback
     copy that to the inquiry data base*/
	//    if (result.inq_res.remt_name_not_required)
	//      p_inq_info->appl_knows_rem_name = true;
	//  }
}

static void add_remote_device(proxy_t *proxy, uint8_t *data, ssize_t data_len) {
	LOG_DEBUG(LOG_TAG, "%s", __func__);

	ssize_t len = REPLY_HEADER_SIZE;
	bool in_use;

	uint8_t addr_type = data[len];
	len += 1;

	uint8_t addr_len = data[len];
	len += 1;

	uint8_t *addr = &data[len];
	len += addr_len;

	size_t eir_size = data[len];
	len += 1;
	// +++++++++++++++++++++++++++++

	uint8_t * eir = data + len;
	len += eir_size;

	//if get IN_USE flag, set to true, else set to false
	if(len < data_len && data[len] == 1)
		in_use = true;
	else
		in_use = false;

	rcm_provide_discovery_results(addr, addr_type, eir, eir_size);
}

// connect ------------------------------------------------------------------------------
bool rcm_device_exists(const RawAddress& bdaddr){
	LOG_DEBUG(LOG_TAG, "%s", __func__);
	rcm_print_raw_bda(bdaddr);
	bool found = rcm_find_device(rcm_proxy.proxy_devices, bdaddr);
	if(found)
		return true;
	return false;
}

/*
 * tBTA_GATTC_API_OPEN used for p_data
 * void bta_gattc_open(tBTA_GATTC_CLCB* p_clcb, tBTA_GATTC_DATA* p_data){

  if (!GATT_Connect(p_clcb->p_rcb->client_if, p_data->api_conn.remote_bda, true,
                    p_data->api_conn.transport, p_data->api_conn.opportunistic,
                    p_data->api_conn.initiating_phys))
	}

bool GATT_Connect(tGATT_IF gatt_if, const RawAddress& bd_addr, bool is_direct,
                  tBT_TRANSPORT transport, bool opportunistic,
                  uint8_t initiating_phys)

void bta_gattc_conn(tBTA_GATTC_CLCB* p_clcb, tBTA_GATTC_DATA* p_data) // p_data is tBTA_GATTC_INT_CONN;

 */

bool rcm_start_remote_connect(const RawAddress& bdaddr, tBTA_GATTC_CLCB* p_clcb){
	// generate and send a connect message to proxy
	if(!rcm_get_initialized()){
		LOG_ERROR(LOG_TAG, "%s RCM is not initialized, ignore all requests to proxy", __func__);
		return false;
	}

	remote_device_t *rdev = rcm_get_device(rcm_proxy.proxy_devices, bdaddr);
	if(rdev != NULL){
		if(rdev->connection_in_progress)
			return true;

		if(rdev->connected){
			tBTA_GATTC_DATA p_data;
			p_data.int_conn.hdr.layer_specific = (uint8_t)rdev->conn_in_progress_for_app->p_rcb->client_if;
			bta_gattc_sm_execute(rdev->conn_in_progress_for_app, BTA_GATTC_INT_CONN_EVT, &p_data);
			return true;
		}
		// And then start to prepare our connect request
		rdev->conn_in_progress_for_app = p_clcb;
		rdev->connection_in_progress = true;
	}
	else if(!rdev){
		LOG_ERROR(LOG_TAG, "%s Device was not found", __func__);
		return false;
	}
	// First, stop discovery on the server
	rcm_stop_remote_scan();

	char app_id[10] = {0};
	get_id(app_id);
	uint8_t appid_len = strlen(app_id);
	LOG_DEBUG(LOG_TAG, "%s id = %s", __func__, app_id);

	char bastr[18];
	rcm_rawaddr_to_str(bdaddr, bastr);

	// [command code] [is_remote] [cache_updated] [bt addr type] [bt address size] [bt address value]
	uint8_t *message = (uint8_t *) malloc(1 + appid_len + 1 + 1 + 1 + 1 + 1 + strlen(bastr));
	size_t length = 0;

	message[length] = appid_len;
	length += 1;

	memcpy(&message[length], app_id, appid_len);
	length += appid_len;

	// Craft a request to connect a given device
	// [command code] [is_remote] [cache_updated] [bt addr type] [bt address size] [bt address value]
	message[length] = (uint8_t) REMOTE_CMD_CONNECT_DEVICE;
	length += 1;

	// This option is coming from bluez's rcm_client and serves to tell the proxy whether the device is connected locally
	// through bt or remote connection is required. It helps proxy to keep in date the information about states of all devices around.
	// For the moment, it is always set to true here TODO
	bool is_remote = true;
	message[length] = is_remote;
	length += 1;

	bool cache_updated = true; //if device connected locally, no need cache file from proxy

	//HUI: adding a flag to let the proxy know whether it should send us a device cache file
	message[length] = cache_updated;
	length += 1;

	message[length] = BLE_ADDR_PUBLIC + 1;
	length += 1;

	message[length] = strlen(bastr);
	length += 1;

	memcpy(&message[length], bastr, strlen(bastr));
	length += strlen(bastr);

	rcm_send_packet(&rcm_proxy, message, length);

	return true;
}

void rcm_provide_connection_results(uint8_t *addr, uint8_t addr_type, uint8_t* p_eir, size_t eir_len) {
	// Call a function corresponding to the HCI_BLE_CONN_COMPLETE_EVT event
	//(uint8_t* p, /*UNUSED_ATTR */uint16_t evt_len, bool enhanced)
	// status[1B], handle[2B], role[1B], bda_type[1B], bda[6B], conn_int[2B], conn_latency[2B], conn_timeout[2B]
	LOG_DEBUG(LOG_TAG, "%s", __func__);

	RawAddress bdaddr = RawAddress((uint8_t (&)[6])addr[0]);
	remote_device_t *rdev = rcm_get_device(rcm_proxy.proxy_devices, bdaddr);
	if(rdev != NULL){
		rdev->connected = true;
	}

	uint8_t p[17];
	uint16_t len = 0;

	p[0] = 0;
	len += 1;

	uint8_t handle[2] = {0x48, 0x00};
	memcpy(&p[len], &handle, 2);
	len += 2;

	p[len] = HCI_ROLE_MASTER;
	len += 1;

	p[len] = BLE_ADDR_PUBLIC;
	len += 1;

	memcpy(&p[len], addr, 6);
	len += 6;

	uint8_t conn_int[2] = {0x28, 0x00};
	memcpy(&p[len], &conn_int, 2);
	len += 2;

	uint8_t conn_latency[2] = {0x00, 0x00};
	memcpy(&p[len], &conn_latency, 2);
	len += 2;

	uint8_t conn_timeout[2] = {0xF4, 0x01};
	memcpy(&p[len], &conn_timeout, 2);
	len += 2;

	rcm_print_msg_hex(len, p);
//	btm_ble_conn_complete(p, len, false);
// void bta_gattc_conn(tBTA_GATTC_CLCB* p_clcb, tBTA_GATTC_DATA* p_data) // p_data is tBTA_GATTC_INT_CONN;
	tBTA_GATTC_DATA p_data;
	p_data.int_conn.hdr.layer_specific = (uint8_t)rdev->conn_in_progress_for_app->p_rcb->client_if;

	rdev->conn_in_progress_for_app->p_srcb->mtu = GATT_DEF_BLE_MTU_SIZE;
	rdev->conn_in_progress_for_app->bta_conn_id = rdev->conn_in_progress_for_app->p_rcb->client_if;
	rdev->conn_in_progress_for_app->transport = BT_TRANSPORT_LE;

/*	bta_gattc_send_open_cback(conn_in_progress_for_app->p_rcb, BTA_GATT_OK, conn_in_progress_for_app->bda,
			conn_in_progress_for_app->bta_conn_id, conn_in_progress_for_app->transport,
			conn_in_progress_for_app->p_srcb->mtu);
*/
	  bta_gattc_sm_execute(rdev->conn_in_progress_for_app, BTA_GATTC_INT_CONN_EVT, &p_data);

//	bta_gattc_conn(conn_in_progress_for_app, &p_data);

}

static void rcm_remote_connect_result(proxy_t *proxy, uint8_t *data, ssize_t data_len) {
	LOG_DEBUG(LOG_TAG, "%s", __func__);

	ssize_t len = REPLY_HEADER_SIZE;

	uint8_t addr_type = data[len];
	len += 1;

	uint8_t addr_len = data[len];
	len += 1;

	uint8_t *addr = &data[len];
	len += addr_len;

	uint8_t eir_size = data[len];
	len += 1;

	uint8_t * eir = data + len; // Shift the server reply by len bytes
	len += eir_size;

	rcm_print_msg_hex(data_len, data);
	rcm_provide_connection_results(addr, addr_type, eir, eir_size);
}

// write --------------------------------------------------------------------------------
// RCM
static void print_hex(uint16_t len, void *p){
        uint8_t *q = (uint8_t*)p;
        for(int i=0; i<len; i++){
        	LOG_DEBUG(LOG_TAG, "%02hhx ", *q++);
//                if(i % 32 == 31)
//                        printf("\n");
        }
//        printf("\n");
}

void rcm_generate_dev_path(char *dev_path, const RawAddress &bda){
	sprintf(dev_path, "/dev_%2.2X_%2.2X_%2.2X_%2.2X_%2.2X_%2.2X/", bda.address[0], bda.address[1], bda.address[2], bda.address[3], bda.address[4], bda.address[5]);
	LOG_DEBUG(LOG_TAG, "%s dev_path = %s", __func__, dev_path);
}

void rcm_generate_descr_path(char *descriptor_path, tBTA_GATTC_DESCRIPTOR* descriptor, bool full){
	uint8_t *s_hdl = (uint8_t *)&(descriptor->characteristic->service->handle);
	uint8_t *c_hdl = (uint8_t *)&(descriptor->characteristic->handle);
	if(full){
		uint8_t *d_hdl = (uint8_t *)&(descriptor->handle);
		sprintf(descriptor_path, "service%2.2x%2.2x/char%2.2x%2.2x/desc%2.2x%2.2x",
				s_hdl[1], s_hdl[0], c_hdl[1], c_hdl[0], d_hdl[1], d_hdl[0]);
	} else{
		sprintf(descriptor_path, "service%2.2x%2.2x/char%2.2x%2.2x",
				s_hdl[1], s_hdl[0], c_hdl[1], c_hdl[0]);
	}
}

void rcm_generate_char_path(char *characteristic_path, tBTA_GATTC_CHARACTERISTIC* characteristic){
	uint8_t *s_hdl = (uint8_t *)&(characteristic->service->handle);
	uint8_t *c_hdl = (uint8_t *)&(characteristic->handle);
	sprintf(characteristic_path, "service%2.2x%2.2x/char%2.2x%2.2x",
			s_hdl[1], s_hdl[0], c_hdl[1], c_hdl[0]);
}

tBTA_GATT_STATUS rcm_remote_write(tBTA_GATTC_CLCB* p_clcb, tGATT_VALUE *attr, tBTA_GATTC_DATA* p_data){
	// Send a message with a value to write to a corresponding uuid (or handle?)
	LOG_DEBUG(LOG_TAG, "%s", __func__);

	if(!rcm_get_initialized()){
		LOG_ERROR(LOG_TAG, "%s RCM is not initialized, ignore all requests to proxy", __func__);
		return BTA_GATT_ERROR;
	}

	remote_device_t *rdev = rcm_get_device(rcm_proxy.proxy_devices, p_clcb->bda);
	if(rdev != NULL){
		if(rdev->connection_in_progress)
			rdev->connection_in_progress = false;
	}

	if(p_data->api_write.p_value)
		print_hex(p_data->api_write.len, p_data->api_write.p_value);
	else
		LOG_DEBUG(LOG_TAG,"%s p_value is empty", __func__);

	write_in_progress = attr;

//	char dev_path[24] = {0};
//	rcm_generate_dev_path(dev_path, p_clcb->bda);

//	char service_path[15] = {0}; // 13
	char characteristic_path[25] = {0}; // serviceXXXX/charYYYY
	char descriptor_path[35] = {0}; // serviceXXXX/charYYYY/descZZZZ
	char complete_path[85] = {0}; // max : serviceXXXX/charYYYY/descZZZZ. The device part dev_AA_AA_AA_AA_AA_AA/ will be generated by proxy when virt btaddr is mapped
	uint8_t send_code = REMOTE_CHAR_WRITE;

	// Check whether the handle corresponds to a characteristic or a descriptor
	tBTA_GATTC_CHARACTERISTIC* characteristic = NULL;
	tBTA_GATTC_DESCRIPTOR*	descriptor = NULL;
	tBT_UUID tar_uuid;
	tar_uuid.len = 2;
	tar_uuid.uu.uuid16 = 0x2902;

//	const tBT_UUID *tar_uuid_ptr = &tar_uuid;
	characteristic = bta_gattc_get_characteristic(p_clcb->bta_conn_id, attr->handle);

	if(characteristic == NULL){
		descriptor = bta_gattc_get_descriptor(p_clcb->bta_conn_id, attr->handle);
		if(descriptor != NULL){
			if(bta_gattc_uuid_compare(&descriptor->uuid, &tar_uuid, true)){
				LOG_DEBUG(LOG_TAG, "%s This descriptor is start notification", __func__);
				rcm_generate_descr_path(descriptor_path, descriptor, false);
				send_code = REMOTE_START_STOP_NOTIF;
			}
			else{
				rcm_generate_descr_path(descriptor_path, descriptor, true);
				send_code = REMOTE_DESC_WRITE;
			}
			sprintf(complete_path, "%s", descriptor_path);
		}
	}else{
		rcm_generate_char_path(characteristic_path, characteristic);
		sprintf(complete_path, "%s", characteristic_path);
	}

	LOG_DEBUG(LOG_TAG, "%s write path = %s", __func__, complete_path);

	char app_id[10] = {0};
	get_id(app_id);
	uint8_t appid_len = strlen(app_id);
	LOG_DEBUG(LOG_TAG, "%s id = %s", __func__, app_id);

	// appid_len [1] + app_id [appid_len] + opcode [1] + path_len[1] + complete_path[path_len] + value_len[2] + value[value_len]
	uint8_t *message = (uint8_t *)malloc(1 + appid_len + 1 + 6 + 1 + strlen(complete_path) + 2 + p_data->api_write.len);
	size_t length = 0;

	message[length] = appid_len;
	length += 1;

	memcpy(&message[length], app_id, appid_len);
	length += appid_len;

	message[length] = REMOTE_CHAR_WRITE;
	length += 1;

	message[length] = send_code; // subcode REMOTE_CHAR_WRITE, REMOTE_DESC_WRITE or REMOTE_START_STOP_NOTIF
	length += 1;

	memcpy(&message[length], &p_clcb->bda, 6);
	length += 6;

	message[length] = strlen(complete_path);
	length += 1;

	memcpy(&message[length], complete_path, strlen(complete_path));
	length += strlen(complete_path);

	memcpy(&message[length], &(p_data->api_write.len), 2);
	length += 2;

	memcpy(&message[length], p_data->api_write.p_value, p_data->api_write.len);
	length += p_data->api_write.len;

	memcpy(&message[length], &(p_data->api_write.handle), sizeof(uint16_t));
	length += sizeof(uint16_t);

	rcm_print_msg_hex(length, message);
	rcm_send_packet(&rcm_proxy, message, length);

	return BTA_GATT_OK;
}

// tGATT_STATUS uses the Success code and error codes from stack/include/gatt_api.h
// e.g. GATT_SUCCESS
/*	static void bta_gattc_cmpl_cback(uint16_t conn_id, tGATTC_OPTYPE op,
	                                 tGATT_STATUS status,
	                                 tGATT_CL_COMPLETE* p_data)

// from stack/include/gatt_api.h:
#define GATTC_OPTYPE_NONE 0
#define GATTC_OPTYPE_DISCOVERY 1
#define GATTC_OPTYPE_READ 2
#define GATTC_OPTYPE_WRITE 3
#define GATTC_OPTYPE_EXE_WRITE 4
#define GATTC_OPTYPE_CONFIG 5
#define GATTC_OPTYPE_NOTIFICATION 6
#define GATTC_OPTYPE_INDICATION 7
typedef uint8_t tGATTC_OPTYPE;
*/

void rcm_write_feedback(proxy_t *proxy, uint8_t *data, ssize_t data_len){
//	conn_in_progress_for_app->bta_conn_id
//  GATTC_OPTYPE_NOTIFICATION or GATTC_OPTYPE_WRITE
//  GATT_SUCCESS
//GATT_DEF_BLE_MTU_SIZE

	// TODO: data here may contain a handle for which the feedback is returned
	int len = 1;
	uint8_t subcode = data[len];
	len += 1;

	uint8_t addr[6];
	memcpy(addr, &data[len], 6);
	len += 6;

	RawAddress bdaddr = RawAddress((uint8_t (&)[6])addr[0]);
	remote_device_t *rdev = rcm_get_device(rcm_proxy.proxy_devices, bdaddr);
	if(rdev == NULL){
		rcm_print_raw_bda(bdaddr);
		LOG_ERROR(LOG_TAG, "%s Device not found", __func__);
		return;
	}

	uint16_t handle;
	memcpy(&handle, &data[len], sizeof(uint16_t));
	len += sizeof(uint16_t);

	uint16_t value_len;
	memcpy(&value_len, &data[len], sizeof(uint16_t));
	len += sizeof(uint16_t);

	tGATT_CL_COMPLETE p_data;

	p_data.att_value.conn_id = rdev->conn_in_progress_for_app->bta_conn_id;
	LOG_INFO(LOG_TAG, "%s p_data.att_value.conn_id=%d", __func__, p_data.att_value.conn_id);

	p_data.att_value.handle = handle;
	LOG_INFO(LOG_TAG, "%s p_data.att_value.conn_id=%d p_data.att_value.handle = %02x",
			__func__, p_data.att_value.conn_id, p_data.att_value.handle);

	p_data.att_value.len = value_len;
	LOG_INFO(LOG_TAG, "%s p_data.att_value.conn_id=%d p_data.att_value.handle = %02x p_data.att_value.len=%d",
				__func__, p_data.att_value.conn_id, p_data.att_value.handle, p_data.att_value.len);

	if(value_len != 0){
		uint8_t value[value_len];
		memcpy(&value, &data[len], value_len);
		len += value_len;
		memcpy(&p_data.att_value.value, value, value_len);
		for(int i=0; i<p_data.att_value.len; i++)
			LOG_INFO(LOG_TAG, "%s value_len = %d value[%d] = %02x", __func__, p_data.att_value.len, i, p_data.att_value.value[i]);
	}
/*	else{
		p_data.handle = handle;
		LOG_INFO(LOG_TAG, "%s p_data.handle = %02x ", __func__, p_data.handle);

		p_data.mtu = (uint16_t)GATT_DEF_BLE_MTU_SIZE;
		LOG_INFO(LOG_TAG, "%s p_data.handle = %02x mtu= %d", __func__, p_data.handle, p_data.mtu);
	}
	*/
	LOG_INFO(LOG_TAG, "%s p_data.handle = %02x mtu= %d p_data.att_value.conn_id=%d p_data.att_value.handle = %02x p_data.att_value.len=%d",
					__func__, p_data.handle, p_data.mtu, p_data.att_value.conn_id, p_data.att_value.handle, p_data.att_value.len);

	uint8_t op_cmpl = GATTC_OPTYPE_WRITE;
	uint8_t status = GATT_SUCCESS;

	if(subcode == REMOTE_START_STOP_NOTIF){
		op_cmpl = GATTC_OPTYPE_NOTIFICATION;
		status = GATT_NOT_ENCRYPTED;
	}

	LOG_INFO(LOG_TAG, "%s handle = %02x", __func__, handle);

	bta_gattc_remote_cmpl_cback(rdev->conn_in_progress_for_app->bta_conn_id, op_cmpl, status, &p_data, rdev->conn_in_progress_for_app->bda);

	/*// to get the char properties
	uint16_t conn_id = conn_in_progress_for_app->bta_conn_id;
	tBTA_GATTC_CHARACTERISTIC* characteristic = NULL;
	tGATTC_OPTYPE op = GATTC_OPTYPE_WRITE;

	characteristic = bta_gattc_get_characteristic(conn_id, handle);

	if(characteristic != NULL){
		if(characteristic->properties & BTA_GATT_CHAR_PROP_BIT_NOTIFY)
			// do something
		else if(characteristic->properties & BTA_GATT_CHAR_PROP_BIT_INDICATE)
			// do something
	}
*/

	// 2) if desc call GATTC_OPTYPE_WRITE as default
	// 3) if char: get characteristic by handle (should be non NULL in p.1)
	// 4) Get char properties
	// 5) check whether the property is GATT_CHAR_PROP_BIT_NOTIFY or GATT_CHAR_PROP_BIT_INDICATE: if(p_char->properties & BTA_GATT_CHAR_PROP_BIT_NOTIFY)
	// 6) if so, GATTC_OPTYPE_NOTIFICATION or GATTC_OPTYPE_INDICATION

	/* definition of characteristic properties from bta/include/bta_gatt_api.h
	 * if GATT_CHAR_PROP_BIT_NOTIFY or GATT_CHAR_PROP_BIT_INDICATE
	#define BTA_GATT_CHAR_PROP_BIT_BROADCAST                                    \
	  GATT_CHAR_PROP_BIT_BROADCAST                                      // 0x01 \

	#define BTA_GATT_CHAR_PROP_BIT_READ GATT_CHAR_PROP_BIT_READ         // 0x02
	#define BTA_GATT_CHAR_PROP_BIT_WRITE_NR GATT_CHAR_PROP_BIT_WRITE_NR // 0x04
	#define BTA_GATT_CHAR_PROP_BIT_WRITE GATT_CHAR_PROP_BIT_WRITE       // 0x08
	#define BTA_GATT_CHAR_PROP_BIT_NOTIFY GATT_CHAR_PROP_BIT_NOTIFY     // 0x10
	#define BTA_GATT_CHAR_PROP_BIT_INDICATE GATT_CHAR_PROP_BIT_INDICATE // 0x20
	#define BTA_GATT_CHAR_PROP_BIT_AUTH GATT_CHAR_PROP_BIT_AUTH         // 0x40
	#define BTA_GATT_CHAR_PROP_BIT_EXT_PROP GATT_CHAR_PROP_BIT_EXT_PROP // 0x80
	typedef uint8_t tBTA_GATT_CHAR_PROP;
	*/
}

// data ---------------------------------------------------------------------------------
// Receive data from proxy and handle it with data_handler().
static int rcm_receive_from_proxy(proxy_t *proxy, int (*message_handler)(proxy_t *, uint8_t *, size_t)) {
  LOG_DEBUG(LOG_TAG, "%s Ready for recv() from %s.", __func__, rcm_proxy_get_address_str(proxy));

  uint8_t buffer[BUFSIZ];
  ssize_t bytes_received;

  bytes_received = recv(proxy->socket, buffer, BUFSIZ, MSG_DONTWAIT);
  rcm_print_msg_hex(bytes_received, buffer);

  if (bytes_received == -1) {
	  if (errno == EAGAIN || errno == EWOULDBLOCK) {
		  LOG_DEBUG(LOG_TAG, "%s peer is not ready right now, try again later.", __func__);
		  return 0;
	  }
	  else {
		  LOG_ERROR(LOG_TAG, "%s recv() from peer error", __func__);
		  return -1;
	  }
  }
  else if (bytes_received == 0) {
	  LOG_DEBUG(LOG_TAG, "%s recv() 0 bytes. Peer gracefully shutdown.", __func__);
	  return -1;
  }

  if(bytes_received)
	  message_handler(proxy, buffer, bytes_received);

  return 0;
}

static int rcm_handle_received_data(proxy_t *proxy, uint8_t *data, size_t data_len) {
  LOG_DEBUG(LOG_TAG, "%s Received data from rcm_proxy", __func__);

  size_t length = 0;

  while(length < data_len - 1)
  {
	  ssize_t pkt_len = data[length];
	  length += 1;

	  // EIR
	  uint8_t code;
	  code = data[length];

	  switch(code)
	  {
	  case REMOTE_CMD_GET_MAC:
	  {
		  rcm_send_mac_address(proxy);
		  break;
	  }
	  case REMOTE_CMD_START_DISCOVERY:
	  {
		  add_remote_device(proxy, &data[length], pkt_len);
		  //			struct eir_data eir_data;
		  //			eir_parse(&eir_data, eir, HCI_MAX_EIR_LENGTH);
		  //			DBG("%s\n",  eir_data.name);
		  //			g_slist_foreach(eir_data.services, print_iterator, "-->");
		  break;
	  }
	  case REMOTE_CMD_CONNECT_DEVICE:
	  {
		  LOG_DEBUG(LOG_TAG, "%s REMOTE_CMD_CONNECT_DEVICE received", __func__);
		  rcm_remote_connect_result(proxy, &data[length], pkt_len);
		  break;
	  }
	  case REMOTE_CMD_DISCONNECT_DEVICE:
	  {
		  // TODO clean some data related to this device...
		  // TODO generate disconnect event for state machine
//		  connected = false;
//		  connection_in_progress = false;
		  break;
	  }
	  case REMOTE_CHAR_WRITE:
	  {
		  LOG_DEBUG(LOG_TAG, "%s REMOTE_CHAR_WRITE received", __func__);
		  rcm_write_feedback(proxy, &data[length], pkt_len);
		  break;
	  }
	  default:
		  LOG_DEBUG(LOG_TAG, "%s Unknown command...", __func__);
		  return 0;
	  }
	  length += pkt_len;
  }
  return 0;
}

static int rcm_send_to_proxy(proxy_t *proxy) {
	LOG_DEBUG(LOG_TAG, "%s Ready for send() to %s.", __func__, rcm_proxy_get_address_str(proxy));
	ssize_t bytes_sent;

	data_t *pkt = rcm_queue_dequeue(proxy->rcm_send_queue);
	if (pkt == NULL) {
		LOG_DEBUG(LOG_TAG, "%s There is nothing to send", __func__);
		return 0;
	}

	LOG_DEBUG(LOG_TAG, "Sending %d bytes... ", (int)pkt->data_len);
	bytes_sent = send(proxy->socket, pkt->data, pkt->data_len, 0);

	if (bytes_sent == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			LOG_DEBUG(LOG_TAG, "%s peer is not ready right now, try again later.", __func__);
			return 0;
		}
		else {
			LOG_ERROR(LOG_TAG, "%s sending error: %s...", __func__, strerror(errno));
			rcm_clear_data_pkt(pkt);
			return -1;
		}
	}
	else if (bytes_sent >= 0) {
		LOG_DEBUG(LOG_TAG, "%s sent %zd bytes", __func__, bytes_sent);
	}

	rcm_clear_data_pkt(pkt);
	return 0;
}
// ---------------------------------------------------------------------------------

// RCM thread and socket management ---------------------------------------------------------------------------------
static int rcm_connect_proxy(proxy_t *rcm_proxy) {
	// create socket
	rcm_proxy->socket = socket(AF_INET, SOCK_STREAM, 0);
	if (rcm_proxy->socket < 0) {
		LOG_ERROR(LOG_TAG, "%s socket()", __func__);
		return -1;
	}

	// set up address
	struct sockaddr_in proxy_addr;
	memset(&proxy_addr, 0, sizeof(proxy_addr));
	proxy_addr.sin_family = AF_INET;

	LOG_INFO(LOG_TAG, "%s Parsing configuration file...", __func__);
	bte_load_rcm_conf(BTE_RCM_CONF_FILE, &proxy_addr);

//	proxy_addr.sin_addr.s_addr = inet_addr(PROXY_IPV4_ADDR);
//	proxy_addr.sin_port = htons(PROXY_LISTEN_PORT);

	rcm_proxy->address = proxy_addr;

	if (connect(rcm_proxy->socket, (struct sockaddr *)&proxy_addr, sizeof(struct sockaddr)) != 0) {
		LOG_ERROR(LOG_TAG, "%s connect() ERROR: %s", __func__, strerror(errno));
		return -1;
	}

	initialized = true;
	rcm_adapter_discovering_cb_register(rcm_start_remote_scan);

	LOG_INFO(LOG_TAG, "%s Connected to the proxy", __func__);

	return 0;
}

static int rcm_build_fd_sets(proxy_t *rcm_proxy, fd_set *read_fds, fd_set *write_fds, fd_set *except_fds) {
	FD_ZERO(read_fds);
	FD_SET(rcm_proxy->socket, read_fds);

	FD_ZERO(write_fds);
	// there is smth to send, set up write_fd for rcm_proxy socket
	if (rcm_proxy->rcm_send_queue->size > 0) {
		LOG_DEBUG(LOG_TAG, "%s rcm_proxy->rcm_send_queue->size = %d", __func__, rcm_proxy->rcm_send_queue->size);
		FD_SET(rcm_proxy->socket, write_fds);
	}

	FD_ZERO(except_fds);
	FD_SET(rcm_proxy->socket, except_fds);

	return 0;
}

// TODO: correctly close thread and the socket here!
static void rcm_clear_thread(int code) {
  rcm_delete_proxy(&rcm_proxy);
  initialized = false;
//  connected = false;
//  connection_in_progress = false;
  LOG_INFO(LOG_TAG, "%s Cleaning thread", __func__);
}

static void rcm_handle_signal_action(int sig_number) {
	if (sig_number == SIGINT) {
		LOG_DEBUG(LOG_TAG, "%s SIGINT was catched!", __func__);
		rcm_clear_thread(EXIT_SUCCESS);
	}
	else if (sig_number == SIGPIPE) {
		LOG_DEBUG(LOG_TAG, "%s SIGPIPE was catched!", __func__);
		rcm_clear_thread(EXIT_SUCCESS);
	}
}

static int rcm_setup_signals() {
  struct sigaction sa;
  sa.sa_handler = rcm_handle_signal_action;
  if (sigaction(SIGINT, &sa, 0) != 0) {
	  LOG_ERROR(LOG_TAG, "%s sigaction() failed", __func__);
    return -1;
  }
  if (sigaction(SIGPIPE, &sa, 0) != 0) {
	  LOG_ERROR(LOG_TAG, "%s sigaction() failed", __func__);
    return -1;
  }

  return 0;
}

static void* rcm_start_thread(void* arg) {
	if (rcm_setup_signals() != 0){
		LOG_DEBUG(LOG_TAG, "%s setup_signals() == 0", __func__);
		return 0;
	}

	rcm_create_proxy(&rcm_proxy);
	if (rcm_connect_proxy(&rcm_proxy) != 0){
		LOG_ERROR(LOG_TAG, "%s connection failed", __func__);
		rcm_clear_thread(EXIT_FAILURE);
		return 0;
	}

	fd_set read_fds;
	fd_set write_fds;
	fd_set except_fds;

	int nfds = rcm_proxy.socket;

	while (1) {
		// Select() updates fd_set's, so we need to build fd_set's before each select()call.
		rcm_build_fd_sets(&rcm_proxy, &read_fds, &write_fds, &except_fds);

		int activity = select(nfds + 1, &read_fds, &write_fds, &except_fds, NULL);

		switch (activity) {
		case -1:
			LOG_ERROR(LOG_TAG, "%s select() returned -1... ERROR: %s", __func__, strerror(errno));
			rcm_clear_thread(EXIT_FAILURE);
			rcm_select_thread_id = -1;
			return 0;

		case 0:
			// you should never get here
			LOG_DEBUG(LOG_TAG, "%s select() returned 0. Should never happen... ERROR: %s", __func__, strerror(errno));
			rcm_clear_thread(EXIT_FAILURE);
			break;

		default:
			LOG_DEBUG(LOG_TAG, "%s FD_ISSET(rcm_proxy.socket, &read_fds)", __func__);
			if (FD_ISSET(rcm_proxy.socket, &read_fds)) {
				if (rcm_receive_from_proxy(&rcm_proxy, &rcm_handle_received_data) != 0)
					rcm_clear_thread(EXIT_FAILURE);
			}

			LOG_DEBUG(LOG_TAG, "%s FD_ISSET(rcm_proxy.socket, &write_fds)", __func__);
			if (FD_ISSET(rcm_proxy.socket, &write_fds)) {
				if (rcm_send_to_proxy(&rcm_proxy) != 0)
					rcm_clear_thread(EXIT_FAILURE);
			}

			LOG_DEBUG(LOG_TAG, "%s FD_ISSET(rcm_proxy.socket, &except_fds)", __func__);
			if (FD_ISSET(rcm_proxy.socket, &except_fds)) {
				LOG_DEBUG(LOG_TAG, "%s except_fds for rcm_proxy", __func__);
				rcm_clear_thread(EXIT_FAILURE);
			}
		}
	}
	LOG_DEBUG(LOG_TAG, "%s quitting thread routine", __func__);
	return 0;
}

static inline pthread_t rcm_create_thread(void* (*start_routine)(void*),
                                      	  void* arg) {
  LOG_DEBUG(LOG_TAG, "RCM: create_thread: entered");
  pthread_attr_t thread_attr;

  pthread_attr_init(&thread_attr);
  pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_JOINABLE);
  pthread_t thread_id = -1;
  if (pthread_create(&thread_id, &thread_attr, start_routine, arg) != 0) {
    BTIF_TRACE_ERROR("RCM: pthread_create : %s", strerror(errno));
    return -1;
  }
  LOG_DEBUG(LOG_TAG, "RCM: create_thread: thread created successfully");
  return thread_id;
}

static void rcm_soc_thread_init(void) {
	LOG_DEBUG(LOG_TAG, "RCM: %s", __func__);

	rcm_select_thread_id = rcm_create_thread(rcm_start_thread, NULL);
}

bool rcm_get_initialized() {
	return initialized;
}

void rcm_init() {
	LOG_INFO(LOG_TAG, "%s Initializing RCM client", __func__);

	if(!rcm_get_initialized()){
//		adapter_stop_discovery_cb_register(stop_remote_scan);

		rcm_soc_thread_init();

		// Subscribe to the callbacks:
		// start_discovery + set_filter(?)
	}
}
