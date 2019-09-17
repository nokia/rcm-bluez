#define LOG_TAG "bt_rcm_conf"

#include <base/logging.h>
#include <stdio.h>
#include <string.h>

//#include "bta_api.h"
#include "btif_common.h"
#include "osi/include/compat.h"
#include "osi/include/config.h"
#include "osi/include/log.h"
#include <arpa/inet.h>

#define PROXY_MAX_NUM 1			// Max Number of supported proxies. Used in configuration file

void bte_load_rcm_conf(const char* p_path, struct sockaddr_in * proxy_addr) {
	CHECK(p_path != NULL);

	config_t* config = config_new(p_path);
	if (!config) {
		LOG_ERROR(LOG_TAG, "%s unable to load RCM config '%s'.", __func__, p_path);
		return;
	}

	for (int i = 1; i <= PROXY_MAX_NUM; ++i) {
		char section_name[16] = {0};
		snprintf(section_name, sizeof(section_name), "PROXY%d", i);

		if (!config_has_section(config, section_name)) {
			LOG_DEBUG(LOG_TAG, "%s no section named %s.", __func__, section_name);
			break;
		}

		const char *ip = config_get_string(config, section_name, "proxyIP", "");
		LOG_INFO(LOG_TAG, "%s PROXY IP = %s", __func__, ip);
		proxy_addr->sin_addr.s_addr = inet_addr(ip);
		proxy_addr->sin_port = htons(config_get_int(config, section_name, "proxyPORT", 1500));
		LOG_INFO(LOG_TAG, "%s PROXY PORT = %d", __func__, proxy_addr->sin_port);

	}

	config_free(config);
}
