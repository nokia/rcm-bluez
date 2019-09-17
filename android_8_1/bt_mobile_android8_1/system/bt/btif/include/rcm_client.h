#ifndef RCM_CLIENT_H
#define RCM_CLIENT_H

#pragma once

#include <netinet/in.h>
#include <stdio.h>
#include "types/raw_address.h"
#include <stdbool.h>
#include "bta/gatt/bta_gattc_int.h"
#include "stack/include/gatt_api.h"
#include "bta/include/bta_gatt_api.h"


//#define PROXY_MAX_NUM 1			// Max Number of supported proxies. Used in configuration file
#define RCM_QUEUE_CAPACITY 100

//#define SENDER_MAXSIZE 128  // TODO: to adjust
//#define DATA_MAXSIZE 512    // TODO: to adjust

#define PROXY_IPV4_ADDR "192.168.0.85" // TODO get the address from a config file in system/bt/config/rcm_config
#define PROXY_LISTEN_PORT 1500

typedef struct {
	uint8_t *data;
	size_t data_len;
} data_t;

typedef struct {
	int front, rear, size;
//	size_t capacity;
	data_t** array;
} data_queue_t;


typedef struct device {
	RawAddress bdaddr;
	bool connection_in_progress;
	bool connected;
	tBTA_GATTC_CLCB* conn_in_progress_for_app;
	struct device *next;
}remote_device_t;

typedef struct list_devices {
	remote_device_t* head;
	int size;
} list_rcm_devices_t;

typedef struct {
  int socket;
  struct sockaddr_in address;
  list_rcm_devices_t *proxy_devices;	// devices available through this given proxy

  /* Messages that waiting for send. */
  data_queue_t *rcm_send_queue;

  /* Buffered sending data.
   *
   * In case we doesn't send a whole data per one call send().
   * And current_sending_byte is a pointer to the part of data that will be sent next call.
   */
  data_t sending_buffer;

  /* The same for the receiving data. */
  data_t receiving_buffer;
} proxy_t;

typedef void (*connect_cb_t)(void *userdata);
typedef void (*discovering_cb_t)(bool start);

void rcm_adapter_discovering_cb_register(discovering_cb_t cb);
void rcm_adapter_stop_discovery_cb_register(discovering_cb_t cb);
bool rcm_device_exists(const RawAddress& bd_addr);
bool rcm_start_remote_connect(const RawAddress& bd_addr, tBTA_GATTC_CLCB* p_clcb);
bool rcm_connection_in_progress(const RawAddress &bdaddr);
bool rcm_connected(const RawAddress &bdaddr);
bool rcm_registered_for_notif();
void rcm_register_for_notif(bool val);
tBTA_GATT_STATUS rcm_remote_write(tBTA_GATTC_CLCB* p_clcb, tGATT_VALUE *attr, tBTA_GATTC_DATA* p_data);
void bta_gattc_remote_cmpl_cback(uint16_t conn_id, tGATTC_OPTYPE op,
                                 tGATT_STATUS status,
                                 tGATT_CL_COMPLETE* p_data, RawAddress &remote_bda);

void bta_gattc_remote_process_indicate(uint16_t conn_id, tGATTC_OPTYPE op,
                                tGATT_CL_COMPLETE* p_data, RawAddress &remote_bda);

void rcm_print_msg_hex(ssize_t num_recv, uint8_t *server_reply);

bool rcm_get_initialized();
void rcm_init(void);

#endif  // RCM_CLIENT_H
