/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Google Inc.
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 */

#include <inttypes.h>

struct btd_gatt_client;

struct btd_gatt_client *btd_gatt_client_new(struct btd_device *device);
void btd_gatt_client_destroy(struct btd_gatt_client *client);

void btd_gatt_client_ready(struct btd_gatt_client *client);
void btd_gatt_client_connected(struct btd_gatt_client *client);
void btd_gatt_client_service_added(struct btd_gatt_client *client,
					struct gatt_db_attribute *attrib);
void btd_gatt_client_service_removed(struct btd_gatt_client *client,
					struct gatt_db_attribute *attrib);
void btd_gatt_client_disconnected(struct btd_gatt_client *client);

typedef void (*btd_gatt_client_service_path_t)(const char *service_path,
							void *user_data);
void btd_gatt_client_foreach_service(struct btd_gatt_client *client,
					btd_gatt_client_service_path_t func,
					void *user_data);

typedef void (*notify_cb_t)(uint16_t value_handle, uint16_t value_len, const uint8_t *value);
void notify_cb_register(notify_cb_t cb);

typedef void (*start_write_cb_t)(unsigned int id, uint16_t handle);
void start_write_cb_register(start_write_cb_t cb);

typedef void (*write_result_cb_t)(unsigned int id);
void write_result_cb_register(write_result_cb_t cb);
