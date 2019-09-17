#include <stdint.h>     // uint*_t
#include <glib.h>       // GSList, g_slist_*
#include <stdbool.h>    // bool
#define _GNU_SOURCE     // asprintf
#include <stdio.h>      // printf
#include <stdlib.h>     // strtol
#include <string.h>     // memset
#include <ctype.h>      // isxdigit
#include <bluetooth/sdp.h> // uuid_t, str2ba, bdaddr_t

//lib/hci.h
#define HCI_MAX_EIR_LENGTH               240
#define HCI_MAX_NAME_LENGTH               248

#include "/home/mando/git/bluez/bluez-5.43/src/shared/util.h" // get_le16...

#define SDP_UUID16            0x19

#define DBG printf
// Compilation
// https://askubuntu.com/questions/90338/how-to-compile-a-helloworld-glib-program
//
// gcc -Wall -o toto toto.c $(pkg-config --cflags --libs glib-2.0)

/*
typedef struct {
    uint8_t b[6];
} __attribute__((packed)) bdaddr_t;
*/

int str2ba(const char *str, bdaddr_t *ba)
{
    int i;

    if (bachk(str) < 0) {
        memset(ba, 0, sizeof(*ba));
        return -1;
    }

    for (i = 5; i >= 0; i--, str += 3)
        ba->b[i] = strtol(str, NULL, 16);

    return 0;
}


////////////// sdp.c

uuid_t *sdp_uuid16_create(uuid_t *u, uint16_t val)
{
    memset(u, 0, sizeof(uuid_t));
    u->type = SDP_UUID16;
    u->value.uuid16 = val;
    return u;
}

uuid_t *sdp_uuid32_create(uuid_t *u, uint32_t val)
{
    memset(u, 0, sizeof(uuid_t));
    u->type = SDP_UUID32;
    u->value.uuid32 = val;
    return u;
}

uuid_t *sdp_uuid128_create(uuid_t *u, const void *val)
{
    memset(u, 0, sizeof(uuid_t));
    u->type = SDP_UUID128;
    memcpy(&u->value.uuid128, val, sizeof(uint128_t));
    return u;
}

static uint128_t bluetooth_base_uuid = {
        .data = {   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
                        0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB }
};
/*
 * 128 to 16 bit and 32 to 16 bit UUID conversion functions
 * yet to be implemented. Note that the input is in NBO in
 * both 32 and 128 bit UUIDs and conversion is needed
 */
void sdp_uuid16_to_uuid128(uuid_t *uuid128, const uuid_t *uuid16)
{
    /*
     * We have a 16 bit value, which needs to be added to
     * bytes 3 and 4 (at indices 2 and 3) of the Bluetooth base
     */
    unsigned short data1;

    /* allocate a 128bit UUID and init to the Bluetooth base UUID */
    uuid128->value.uuid128 = bluetooth_base_uuid;
    uuid128->type = SDP_UUID128;

    /* extract bytes 2 and 3 of 128bit BT base UUID */
    memcpy(&data1, &bluetooth_base_uuid.data[2], 2);

    /* add the given UUID (16 bits) */
    data1 += htons(uuid16->value.uuid16);

    /* set bytes 2 and 3 of the 128 bit value */
    memcpy(&uuid128->value.uuid128.data[2], &data1, 2);
}

void sdp_uuid32_to_uuid128(uuid_t *uuid128, const uuid_t *uuid32)
{
    /*
     * We have a 32 bit value, which needs to be added to
     * bytes 1->4 (at indices 0 thru 3) of the Bluetooth base
     */
    unsigned int data0;

    /* allocate a 128bit UUID and init to the Bluetooth base UUID */
    uuid128->value.uuid128 = bluetooth_base_uuid;
    uuid128->type = SDP_UUID128;

    /* extract first 4 bytes */
    memcpy(&data0, &bluetooth_base_uuid.data[0], 4);

    /* add the given UUID (32bits) */
    data0 += htonl(uuid32->value.uuid32);

    /* set the 4 bytes of the 128 bit value */
    memcpy(&uuid128->value.uuid128.data[0], &data0, 4);
}

char *bt_uuid2string(uuid_t *uuid)
{
    char *str;
    uuid_t uuid128;
    unsigned int data0;
    unsigned short data1;
    unsigned short data2;
    unsigned short data3;
    unsigned int data4;
    unsigned short data5;
    int err;

    if (!uuid)
        return NULL;

    switch (uuid->type) {
        case SDP_UUID16:
            sdp_uuid16_to_uuid128(&uuid128, uuid);
            break;
        case SDP_UUID32:
            sdp_uuid32_to_uuid128(&uuid128, uuid);
            break;
        case SDP_UUID128:
            memcpy(&uuid128, uuid, sizeof(uuid_t));
            break;
        default:
            /* Type of UUID unknown */
            return NULL;
    }

    memcpy(&data0, &uuid128.value.uuid128.data[0], 4);
    memcpy(&data1, &uuid128.value.uuid128.data[4], 2);
    memcpy(&data2, &uuid128.value.uuid128.data[6], 2);
    memcpy(&data3, &uuid128.value.uuid128.data[8], 2);
    memcpy(&data4, &uuid128.value.uuid128.data[10], 4);
    memcpy(&data5, &uuid128.value.uuid128.data[14], 2);

    err = asprintf(&str, "%.8x-%.4x-%.4x-%.4x-%.8x%.4x",
            ntohl(data0), ntohs(data1),
            ntohs(data2), ntohs(data3),
            ntohl(data4), ntohs(data5));
    if (err < 0)
        return NULL;

    return str;
}

int bachk(const char *str)
{
    if (!str)
        return -1;

    if (strlen(str) != 17)
        return -1;

    while (*str) {
        if (!isxdigit(*str++))
            return -1;

        if (!isxdigit(*str++))
            return -1;

        if (*str == 0)
            break;

        if (*str++ != ':')
            return -1;
    }

    return 0;
}

/*
int str2ba(const char *str, bdaddr_t *ba)
{
    int i;

    if (bachk(str) < 0) {
        memset(ba, 0, sizeof(*ba));
        return -1;
    }

    for (i = 5; i >= 0; i--, str += 3)
        ba->b[i] = strtol(str, NULL, 16);

    return 0;
}
*/

////////////////eir.*
//#include "lib/sdp.h"

#define EIR_FLAGS                   0x01  /* flags */
#define EIR_UUID16_SOME             0x02  /* 16-bit UUID, more available */
#define EIR_UUID16_ALL              0x03  /* 16-bit UUID, all listed */
#define EIR_UUID32_SOME             0x04  /* 32-bit UUID, more available */
#define EIR_UUID32_ALL              0x05  /* 32-bit UUID, all listed */
#define EIR_UUID128_SOME            0x06  /* 128-bit UUID, more available */
#define EIR_UUID128_ALL             0x07  /* 128-bit UUID, all listed */
#define EIR_NAME_SHORT              0x08  /* shortened local name */
#define EIR_NAME_COMPLETE           0x09  /* complete local name */
#define EIR_TX_POWER                0x0A  /* transmit power level */
#define EIR_CLASS_OF_DEV            0x0D  /* Class of Device */
#define EIR_SSP_HASH                0x0E  /* SSP Hash */
#define EIR_SSP_RANDOMIZER          0x0F  /* SSP Randomizer */
#define EIR_DEVICE_ID               0x10  /* device ID */
#define EIR_SOLICIT16               0x14  /* LE: Solicit UUIDs, 16-bit */
#define EIR_SOLICIT128              0x15  /* LE: Solicit UUIDs, 128-bit */
#define EIR_SVC_DATA16              0x16  /* LE: Service data, 16-bit UUID */
#define EIR_PUB_TRGT_ADDR           0x17  /* LE: Public Target Address */
#define EIR_RND_TRGT_ADDR           0x18  /* LE: Random Target Address */
#define EIR_GAP_APPEARANCE          0x19  /* GAP appearance */
#define EIR_SOLICIT32               0x1F  /* LE: Solicit UUIDs, 32-bit */
#define EIR_SVC_DATA32              0x20  /* LE: Service data, 32-bit UUID */
#define EIR_SVC_DATA128             0x21  /* LE: Service data, 128-bit UUID */
#define EIR_MANUFACTURER_DATA       0xFF  /* Manufacturer Specific Data */

/* Flags Descriptions */
#define EIR_LIM_DISC                0x01 /* LE Limited Discoverable Mode */
#define EIR_GEN_DISC                0x02 /* LE General Discoverable Mode */
#define EIR_BREDR_UNSUP             0x04 /* BR/EDR Not Supported */
#define EIR_CONTROLLER              0x08 /* Simultaneous LE and BR/EDR to Same
                        Device Capable (Controller) */
#define EIR_SIM_HOST                0x10 /* Simultaneous LE and BR/EDR to Same
                        Device Capable (Host) */

#define EIR_SD_MAX_LEN              238  /* 240 (EIR) - 2 (len) */
#define EIR_MSD_MAX_LEN             236  /* 240 (EIR) - 2 (len & type) - 2 */

struct eir_msd {
    uint16_t company;
    uint8_t data[EIR_MSD_MAX_LEN];
    uint8_t data_len;
};

struct eir_sd {
    char *uuid;
    uint8_t data[EIR_SD_MAX_LEN];
    uint8_t data_len;
};

struct eir_data {
    GSList *services;
    unsigned int flags;
    char *name;
    uint32_t class;
    uint16_t appearance;
    bool name_complete;
    int8_t tx_power;
    uint8_t *hash;
    uint8_t *randomizer;
    bdaddr_t addr;
    uint16_t did_vendor;
    uint16_t did_product;
    uint16_t did_version;
    uint16_t did_source;
    GSList *msd_list;
    GSList *sd_list;
};


#include <errno.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <glib.h>

//#include "lib/bluetooth.h"
//#include "lib/hci.h"
//#include "lib/sdp.h"

//#include "src/shared/util.h"
//#include "uuid-helper.h"
//#include "eir.h"

#define EIR_OOB_MIN (2 + 6)

static void sd_free(void *data)
{
    struct eir_sd *sd = data;

    free(sd->uuid);
    g_free(sd);
}

void eir_data_free(struct eir_data *eir)
{
    g_slist_free_full(eir->services, free);
    eir->services = NULL;
    g_free(eir->name);
    eir->name = NULL;
    g_free(eir->hash);
    eir->hash = NULL;
    g_free(eir->randomizer);
    eir->randomizer = NULL;
    g_slist_free_full(eir->msd_list, g_free);
    eir->msd_list = NULL;
    g_slist_free_full(eir->sd_list, sd_free);
    eir->sd_list = NULL;
}

static void eir_parse_uuid16(struct eir_data *eir, const void *data,
                                uint8_t len)
{
    const uint16_t *uuid16 = data;
    uuid_t service;
    char *uuid_str;
    unsigned int i;

    service.type = SDP_UUID16;
    for (i = 0; i < len / 2; i++, uuid16++) {
        service.value.uuid16 = get_le16(uuid16);

        uuid_str = bt_uuid2string(&service);
        if (!uuid_str)
            continue;
        eir->services = g_slist_append(eir->services, uuid_str);
    }
}

static void eir_parse_uuid32(struct eir_data *eir, const void *data,
                                uint8_t len)
{
    const uint32_t *uuid32 = data;
    uuid_t service;
    char *uuid_str;
    unsigned int i;

    service.type = SDP_UUID32;
    for (i = 0; i < len / 4; i++, uuid32++) {
        service.value.uuid32 = get_le32(uuid32);

        uuid_str = bt_uuid2string(&service);
        if (!uuid_str)
            continue;
        eir->services = g_slist_append(eir->services, uuid_str);
    }
}

static void eir_parse_uuid128(struct eir_data *eir, const uint8_t *data,
                                uint8_t len)
{
    const uint8_t *uuid_ptr = data;
    uuid_t service;
    char *uuid_str;
    unsigned int i;
    int k;

    service.type = SDP_UUID128;
    printf("eir_parse_uuid128: len = %zu len/16 = %zu\n", (size_t) len, (size_t) len/16);
    for (i = 0; i < len / 16; i++) {
        printf("eir_parse_uuid128: extract from @ = %p\n", uuid_ptr);
        for (k = 0; k < 16; k++) {
            service.value.uuid128.data[k] = uuid_ptr[16 - k - 1];
            printf("eir_parse_uuid128: data[%d] = %02x\n", k, service.value.uuid128.data[k]);
        }
        uuid_str = bt_uuid2string(&service);
        if (!uuid_str) {
            printf("eir_parse_uuid128: no uuid_str, continue\n");
            continue;
        }
        printf("eir_parse_uuid128: extracted uuid = %s\n", uuid_str);
        eir->services = g_slist_append(eir->services, uuid_str);
        uuid_ptr += 16;
    }
}

static char *name2utf8(const uint8_t *name, uint8_t len)
{
    char utf8_name[HCI_MAX_NAME_LENGTH + 2];
    int i;

    if (g_utf8_validate((const char *) name, len, NULL))
        return g_strndup((char *) name, len);

    memset(utf8_name, 0, sizeof(utf8_name));
    strncpy(utf8_name, (char *) name, len);

    /* Assume ASCII, and replace all non-ASCII with spaces */
    for (i = 0; utf8_name[i] != '\0'; i++) {
        if (!isascii(utf8_name[i]))
            utf8_name[i] = ' ';
    }

    /* Remove leading and trailing whitespace characters */
    g_strstrip(utf8_name);

    return g_strdup(utf8_name);
}

static void eir_parse_msd(struct eir_data *eir, const uint8_t *data,
                                uint8_t len)
{
    struct eir_msd *msd;

    if (len < 2 || len > 2 + sizeof(msd->data))
        return;

    msd = g_malloc(sizeof(*msd));
    msd->company = get_le16(data);
    msd->data_len = len - 2;
    memcpy(&msd->data, data + 2, msd->data_len);

    eir->msd_list = g_slist_append(eir->msd_list, msd);
}

static void eir_parse_sd(struct eir_data *eir, uuid_t *service,
                    const uint8_t *data, uint8_t len)
{
    struct eir_sd *sd;
    char *uuid;

    uuid = bt_uuid2string(service);
    if (!uuid)
        return;

    sd = g_malloc(sizeof(*sd));
    sd->uuid = uuid;
    sd->data_len = len;
    memcpy(&sd->data, data, sd->data_len);

    eir->sd_list = g_slist_append(eir->sd_list, sd);
}

static void eir_parse_uuid16_data(struct eir_data *eir, const uint8_t *data,
                                uint8_t len)
{
    uuid_t service;

    if (len < 2 || len > EIR_SD_MAX_LEN)
        return;

    service.type = SDP_UUID16;
    service.value.uuid16 = get_le16(data);
    eir_parse_sd(eir, &service, data + 2, len - 2);
}

static void eir_parse_uuid32_data(struct eir_data *eir, const uint8_t *data,
                                uint8_t len)
{
    uuid_t service;

    if (len < 4 || len > EIR_SD_MAX_LEN)
        return;

    service.type = SDP_UUID32;
    service.value.uuid32 = get_le32(data);
    eir_parse_sd(eir, &service, data + 4, len - 4);
}

static void eir_parse_uuid128_data(struct eir_data *eir, const uint8_t *data,
                                uint8_t len)
{
    uuid_t service;
    int k;

    if (len < 16 || len > EIR_SD_MAX_LEN)
        return;

    service.type = SDP_UUID128;

    for (k = 0; k < 16; k++)
        service.value.uuid128.data[k] = data[16 - k - 1];

    eir_parse_sd(eir, &service, data + 16, len - 16);
}

void eir_parse(struct eir_data *eir, const uint8_t *eir_data, uint8_t eir_len)
{
    printf("eir_parse: =============================================\n");
    printf("eir_parse: @ = %p size = %zu\n", eir_data, (size_t) eir_len);
    uint16_t len = 0;

    eir->flags = 0;
    eir->tx_power = 127;

    /* No EIR data to parse */
    if (eir_data == NULL)
        return;

    while (len < eir_len - 1) {
        printf("eir_parse: ---------------------------------------------\n");
        printf("eir_parse: BEGIN READ FIELD %p\n", eir_data);
        uint8_t field_len = eir_data[0];
        const uint8_t *data;
        uint8_t data_len;

        /* Check for the end of EIR */
        if (field_len == 0) {
            printf("eir_parse: ERROR! empty field\n");
            break;
        }

        len += field_len + 1;
        printf("eir_parse: the next field will starts at @ = %p\n", eir_data + len);

        /* Do not continue EIR Data parsing if got incorrect length */
        if (len > eir_len) {
            printf("eir_parse: ERROR! len = %zu > eir_len = %zu\n", (size_t) len, (size_t) eir_len);
            break;
        }

        data = &eir_data[2];
        data_len = field_len - 1;
        printf("eir_parse: the current field as a value of size %zu and of type %zu\n", (size_t) data_len, (size_t) eir_data[1]);

        switch (eir_data[1]) {
            case EIR_UUID16_SOME:
            case EIR_UUID16_ALL:
                printf("eir_parse: uint16\n");
                eir_parse_uuid16(eir, data, data_len);
                break;

            case EIR_UUID32_SOME:
            case EIR_UUID32_ALL:
                printf("eir_parse: uint32\n");
                eir_parse_uuid32(eir, data, data_len);
                break;

            case EIR_UUID128_SOME:
            case EIR_UUID128_ALL:
                printf("eir_parse: uint128\n");
                eir_parse_uuid128(eir, data, data_len);
                break;

            case EIR_FLAGS:
                if (data_len > 0)
                    eir->flags = *data;
                break;

            case EIR_NAME_SHORT:
            case EIR_NAME_COMPLETE:
                printf("eir_parse: name\n");
                /* Some vendors put a NUL byte terminator into
                 * the name */
                while (data_len > 0 && data[data_len - 1] == '\0')
                    data_len--;

                g_free(eir->name);

                eir->name = name2utf8(data, data_len);
                eir->name_complete = eir_data[1] == EIR_NAME_COMPLETE;
                break;

            case EIR_TX_POWER:
                if (data_len < 1)
                    break;
                eir->tx_power = (int8_t) data[0];
                break;

            case EIR_CLASS_OF_DEV:
                if (data_len < 3)
                    break;
                eir->class = data[0] | (data[1] << 8) |
                    (data[2] << 16);
                break;

            case EIR_GAP_APPEARANCE:
                if (data_len < 2)
                    break;
                eir->appearance = get_le16(data);
                break;

            case EIR_SSP_HASH:
                if (data_len < 16)
                    break;
                eir->hash = g_memdup(data, 16);
                break;

            case EIR_SSP_RANDOMIZER:
                if (data_len < 16)
                    break;
                eir->randomizer = g_memdup(data, 16);
                break;

            case EIR_DEVICE_ID:
                if (data_len < 8)
                    break;

                eir->did_source = data[0] | (data[1] << 8);
                eir->did_vendor = data[2] | (data[3] << 8);
                eir->did_product = data[4] | (data[5] << 8);
                eir->did_version = data[6] | (data[7] << 8);
                break;

            case EIR_SVC_DATA16:
                eir_parse_uuid16_data(eir, data, data_len);
                break;

            case EIR_SVC_DATA32:
                eir_parse_uuid32_data(eir, data, data_len);
                break;

            case EIR_SVC_DATA128:
                eir_parse_uuid128_data(eir, data, data_len);
                break;

            case EIR_MANUFACTURER_DATA:
                eir_parse_msd(eir, data, data_len);
                break;

        }

        eir_data += field_len + 1;

        printf("eir_parse: END READ FIELD: continue if len < eir_len - 1: len = %zu ; eir_len - 1 = %zu\n", (size_t) len, (size_t) eir_len - 1);
    }
    printf("eir_parse: =============================================\n");
}

int eir_parse_oob(struct eir_data *eir, uint8_t *eir_data, uint16_t eir_len)
{

    if (eir_len < EIR_OOB_MIN)
        return -1;

    if (eir_len != get_le16(eir_data))
        return -1;

    eir_data += sizeof(uint16_t);
    eir_len -= sizeof(uint16_t);

    memcpy(&eir->addr, eir_data, sizeof(bdaddr_t));
    eir_data += sizeof(bdaddr_t);
    eir_len -= sizeof(bdaddr_t);

    /* optional OOB EIR data */
    if (eir_len > 0)
        eir_parse(eir, eir_data, eir_len);

    return 0;
}

#define SIZEOF_UUID128 16

static void eir_generate_uuid128(sdp_list_t *list, uint8_t *ptr,
                            uint16_t *eir_len)
{
    int i, k, uuid_count = 0;
    uint16_t len = *eir_len;
    uint8_t *uuid128;
    bool truncated = false;

    /* Store UUIDs in place, skip 2 bytes to write type and length later */
    uuid128 = ptr + 2;

    for (; list; list = list->next) {
        sdp_record_t *rec = list->data;
        uuid_t *uuid = &rec->svclass;
        uint8_t *uuid128_data = uuid->value.uuid128.data;

        if (uuid->type != SDP_UUID128)
            continue;

        /* Stop if not enough space to put next UUID128 */
        if ((len + 2 + SIZEOF_UUID128) > HCI_MAX_EIR_LENGTH) {
            truncated = true;
            break;
        }

        /* Check for duplicates, EIR data is Little Endian */
        for (i = 0; i < uuid_count; i++) {
            for (k = 0; k < SIZEOF_UUID128; k++) {
                if (uuid128[i * SIZEOF_UUID128 + k] !=
                    uuid128_data[SIZEOF_UUID128 - 1 - k])
                    break;
            }
            if (k == SIZEOF_UUID128)
                break;
        }

        if (i < uuid_count)
            continue;

        /* EIR data is Little Endian */
        for (k = 0; k < SIZEOF_UUID128; k++)
            uuid128[uuid_count * SIZEOF_UUID128 + k] =
                uuid128_data[SIZEOF_UUID128 - 1 - k];

        len += SIZEOF_UUID128;
        uuid_count++;
    }

    if (uuid_count > 0 || truncated) {
        /* EIR Data length */
        ptr[0] = (uuid_count * SIZEOF_UUID128) + 1;
        /* EIR Data type */
        ptr[1] = truncated ? EIR_UUID128_SOME : EIR_UUID128_ALL;
        len += 2;
        *eir_len = len;
    }
}

int eir_create_oob(const bdaddr_t *addr, const char *name, uint32_t cod,
            const uint8_t *hash, const uint8_t *randomizer,
            uint16_t did_vendor, uint16_t did_product,
            uint16_t did_version, uint16_t did_source,
            sdp_list_t *uuids, uint8_t *data)
{
    sdp_list_t *l;
    uint8_t *ptr = data;
    uint16_t eir_optional_len = 0;
    uint16_t eir_total_len;
    uint16_t uuid16[HCI_MAX_EIR_LENGTH / 2];
    int i, uuid_count = 0;
    bool truncated = false;
    size_t name_len;

    eir_total_len =  sizeof(uint16_t) + sizeof(bdaddr_t);
    ptr += sizeof(uint16_t);

    memcpy(ptr, addr, sizeof(bdaddr_t));
    ptr += sizeof(bdaddr_t);

    if (cod > 0) {
        uint8_t class[3];

        class[0] = (uint8_t) cod;
        class[1] = (uint8_t) (cod >> 8);
        class[2] = (uint8_t) (cod >> 16);

        *ptr++ = 4;
        *ptr++ = EIR_CLASS_OF_DEV;

        memcpy(ptr, class, sizeof(class));
        ptr += sizeof(class);

        eir_optional_len += sizeof(class) + 2;
    }

    if (hash) {
        *ptr++ = 17;
        *ptr++ = EIR_SSP_HASH;

        memcpy(ptr, hash, 16);
        ptr += 16;

        eir_optional_len += 16 + 2;
    }

    if (randomizer) {
        *ptr++ = 17;
        *ptr++ = EIR_SSP_RANDOMIZER;

        memcpy(ptr, randomizer, 16);
        ptr += 16;

        eir_optional_len += 16 + 2;
    }

    name_len = strlen(name);

    if (name_len > 0) {
        /* EIR Data type */
        if (name_len > 48) {
            name_len = 48;
            ptr[1] = EIR_NAME_SHORT;
        } else
            ptr[1] = EIR_NAME_COMPLETE;

        /* EIR Data length */
        ptr[0] = name_len + 1;

        memcpy(ptr + 2, name, name_len);

        eir_optional_len += (name_len + 2);
        ptr += (name_len + 2);
    }

    if (did_vendor != 0x0000) {
        *ptr++ = 9;
        *ptr++ = EIR_DEVICE_ID;
        *ptr++ = (did_source & 0x00ff);
        *ptr++ = (did_source & 0xff00) >> 8;
        *ptr++ = (did_vendor & 0x00ff);
        *ptr++ = (did_vendor & 0xff00) >> 8;
        *ptr++ = (did_product & 0x00ff);
        *ptr++ = (did_product & 0xff00) >> 8;
        *ptr++ = (did_version & 0x00ff);
        *ptr++ = (did_version & 0xff00) >> 8;
        eir_optional_len += 10;
    }

    /* Group all UUID16 types */
    for (l = uuids; l != NULL; l = l->next) {
        sdp_record_t *rec = l->data;
        uuid_t *uuid = &rec->svclass;

        if (uuid->type != SDP_UUID16)
            continue;

        if (uuid->value.uuid16 < 0x1100)
            continue;

        if (uuid->value.uuid16 == PNP_INFO_SVCLASS_ID)
            continue;

        /* Stop if not enough space to put next UUID16 */
        if ((eir_optional_len + 2 + sizeof(uint16_t)) >
                HCI_MAX_EIR_LENGTH) {
            truncated = true;
            break;
        }

        /* Check for duplicates */
        for (i = 0; i < uuid_count; i++)
            if (uuid16[i] == uuid->value.uuid16)
                break;

        if (i < uuid_count)
            continue;

        uuid16[uuid_count++] = uuid->value.uuid16;
        eir_optional_len += sizeof(uint16_t);
    }

    if (uuid_count > 0) {
        /* EIR Data length */
        ptr[0] = (uuid_count * sizeof(uint16_t)) + 1;
        /* EIR Data type */
        ptr[1] = truncated ? EIR_UUID16_SOME : EIR_UUID16_ALL;

        ptr += 2;
        eir_optional_len += 2;

        for (i = 0; i < uuid_count; i++) {
            *ptr++ = (uuid16[i] & 0x00ff);
            *ptr++ = (uuid16[i] & 0xff00) >> 8;
        }
    }

    /* Group all UUID128 types */
    if (eir_optional_len <= HCI_MAX_EIR_LENGTH - 2)
        eir_generate_uuid128(uuids, ptr, &eir_optional_len);

    eir_total_len += eir_optional_len;

    /* store total length */
    put_le16(eir_total_len, data);

    return eir_total_len;
}
////////////////eir.*

/////////// uuid-helper.c

static struct {
    const char  *name;
    uint16_t    class;
} bt_services[] = {
    { "pbap",   PBAP_SVCLASS_ID         },
    { "sap",    SAP_SVCLASS_ID          },
    { "ftp",    OBEX_FILETRANS_SVCLASS_ID   },
    { "bpp",    BASIC_PRINTING_SVCLASS_ID   },
    { "bip",    IMAGING_SVCLASS_ID      },
    { "synch",  IRMC_SYNC_SVCLASS_ID        },
    { "dun",    DIALUP_NET_SVCLASS_ID       },
    { "opp",    OBEX_OBJPUSH_SVCLASS_ID     },
    { "fax",    FAX_SVCLASS_ID          },
    { "spp",    SERIAL_PORT_SVCLASS_ID      },
    { "hsp",    HEADSET_SVCLASS_ID      },
    { "hsp-hs", HEADSET_SVCLASS_ID      },
    { "hsp-ag", HEADSET_AGW_SVCLASS_ID      },
    { "hfp",    HANDSFREE_SVCLASS_ID        },
    { "hfp-hf", HANDSFREE_SVCLASS_ID        },
    { "hfp-ag", HANDSFREE_AGW_SVCLASS_ID    },
    { "pbap-pce",   PBAP_PCE_SVCLASS_ID     },
    { "pbap-pse",   PBAP_PSE_SVCLASS_ID     },
    { "map-mse",    MAP_MSE_SVCLASS_ID      },
    { "map-mas",    MAP_MSE_SVCLASS_ID      },
    { "map-mce",    MAP_MCE_SVCLASS_ID      },
    { "map-mns",    MAP_MCE_SVCLASS_ID      },
    { "gnss",   GNSS_SERVER_SVCLASS_ID      },
    { }
};

static inline bool is_uuid128(const char *string)
{
    return (strlen(string) == 36 &&
            string[8] == '-' &&
            string[13] == '-' &&
            string[18] == '-' &&
            string[23] == '-');
}

static uint16_t name2class(const char *pattern)
{
    int i;

    for (i = 0; bt_services[i].name; i++) {
        if (strcasecmp(bt_services[i].name, pattern) == 0)
            return bt_services[i].class;
    }

    return 0;
}


static int string2uuid16(uuid_t *uuid, const char *string)
{
    int length = strlen(string);
    char *endptr = NULL;
    uint16_t u16;

    if (length != 4 && length != 6)
        return -EINVAL;

    u16 = strtol(string, &endptr, 16);
    if (endptr && *endptr == '\0') {
        sdp_uuid16_create(uuid, u16);
        return 0;
    }

    return -EINVAL;
}

int bt_string2uuid(uuid_t *uuid, const char *string)
{
    uint32_t data0, data4;
    uint16_t data1, data2, data3, data5;

    if (is_uuid128(string) &&
            sscanf(string, "%08x-%04hx-%04hx-%04hx-%08x%04hx",
                &data0, &data1, &data2, &data3, &data4, &data5) == 6) {
        uint8_t val[16];

        data0 = htonl(data0);
        data1 = htons(data1);
        data2 = htons(data2);
        data3 = htons(data3);
        data4 = htonl(data4);
        data5 = htons(data5);

        memcpy(&val[0], &data0, 4);
        memcpy(&val[4], &data1, 2);
        memcpy(&val[6], &data2, 2);
        memcpy(&val[8], &data3, 2);
        memcpy(&val[10], &data4, 4);
        memcpy(&val[14], &data5, 2);

        sdp_uuid128_create(uuid, val);

        return 0;
    } else {
        uint16_t class = name2class(string);
        if (class) {
            sdp_uuid16_create(uuid, class);
            return 0;
        }

        return string2uuid16(uuid, string);
    }
}

/////////// uuid-helper.c

void print_iterator(gpointer item, gpointer prefix) {
     printf("%s %s\n", (const char*) prefix, (const char *) item);
}

void update_found_devices(void * adapter,//struct btd_adapter *adapter,
        const bdaddr_t *bdaddr,
        uint8_t bdaddr_type, int8_t rssi,
        bool confirm, bool legacy,
        bool not_connectable,
        const uint8_t *_data, uint8_t data_len)
{
    // data is a: const struct eir_data *
    struct eir_data eir_data;
    bool name_known, discoverable;

    memset(&eir_data, 0, sizeof(struct eir_data));

    //void eir_parse(struct eir_data *eir, const uint8_t *eir_data, uint8_t eir_len)
    eir_parse(&eir_data, _data, data_len);
    //memcpy(&eir_data, data, data_len);

    //const struct eir_data * _data = (const struct eir_data *) data;
    //DBG("MARCO3 print name %s services %s\n", (const char *) eir_data.name, (const char *) eir_data.services->data);
    printf("name    : '%s'\n", (const char *) eir_data.name);
    printf("services:\n");
    g_slist_foreach(eir_data.services, print_iterator, "  ");
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////

/*
struct eir_data {
    GSList *services;
    unsigned int flags;
    char *name;
    uint32_t class;
    uint16_t appearance;
    bool name_complete;
    int8_t tx_power;
    uint8_t *hash;
    uint8_t *randomizer;
    bdaddr_t addr;
    uint16_t did_vendor;
    uint16_t did_product;
    uint16_t did_version;
    uint16_t did_source;
    GSList *msd_list;
    GSList *sd_list;
};
*/

/*
void * ntoh128(void * _out, void * _in) {
    uint32_t * in  = (uint32_t *) in;
    uint32_t * out = (uint32_t *) out;
    uint8_t i;
    for (i = 0; i < 4; i++) {
        *out++ = ntohl(in[3-i]);
    }
    return out;
}
*/

void to_eir_GSList_cb_write_uint128(gpointer item, gpointer pbuffer) {
    // TODO only write if the item is uint128_t
    printf("to_eir_GSList_cb_write_uint128: begin: @ = %p\n", * (uint8_t **) pbuffer);

    // Read the string. Each consecutive pair of character corresponds to a byte.
    // bt_string2uuid(*(uuid_t **) pbuffer, item);
    printf("item = '%s'\n", (char *) item);
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

    printf("to_eir_GSList_cb_write_uint128: end  : @ = %p\n", * (uint8_t **) pbuffer);
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

void to_eir_string_write(gpointer item, gpointer pbuffer) {
    // In practice, item is a char *, pbuffer is an uint8_t **.
    size_t len = strlen(item) + sizeof(char);                       // The field contains the type, the string null terminated.
    printf("to_eir_string_write: begin: @ = %p\n", * (uint8_t **) pbuffer);
    *(*(uint8_t **) pbuffer)++ = (uint8_t) len + sizeof(uint8_t);   // Write size and move 1 byte forward. Do not forget the type.
    *(*(uint8_t **) pbuffer)++ = EIR_NAME_SHORT;                    // Write type and move 1 byte forward.
    memcpy(*(uint8_t **) pbuffer, item, len);                       // Write the string and its ending '\0'.
    *(uint8_t **) pbuffer += len;                                   // Move at the end of the string.
    printf("to_eir_string_write: end  : @ = %p\n", * (uint8_t **) pbuffer);
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

gpointer to_eir(const struct eir_data * eir_data, gpointer buffer, size_t *pbuffer_size) {
    size_t eir_size = 0;
    gpointer ret = buffer;
    uint8_t num_services = 0;

    // Pre-requisites:
    //
    // An EIR is made of a sequence of fields.
    //
    // Each field is made as follow:
    // - 1 byte for the type   (uint8_t)
    // - 1 byte for the size s (uint8_t)
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
        eir_size += 2;                          // size, type
        eir_size += strlen(eir_data->name) + 1; // value
    }
    printf("name     : size_needed = %zu\n", eir_size);

    if (eir_data->services) {
        num_services = (uint8_t) g_slist_length(eir_data->services);
        eir_size += 2;                      // size, type
        eir_size += num_services * 128/8;   // values
    }
    printf("services : size_needed = %zu\n", eir_size);

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
    printf("ALLOC: buffer        = %p\n",  buffer);
    printf("ALLOC: *pbuffer_size = %zu\n", *pbuffer_size);

    printf("services will start @ = %p\n", buffer + 2 + strlen(eir_data->name) + 1);

    // 3) Second pass: write into the buffer the EIR.

    if (eir_data->name) {
        printf("WRITE FIELD: name, @ = %p\n", buffer); // DEBUG
        const uint8_t *begin_field = buffer; // DEBUG
        to_eir_string_write(eir_data->name, &buffer);
        printf("s:%d t:%d v:'%s'\n", begin_field[0], begin_field[1], begin_field+2); // DEBUG
    }

    if (eir_data->services) {
        printf("WRITE FIELD: services, @ = %p\n", buffer); // DEBUG
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

int main() {
    struct eir_data eir_data;
    memset(&eir_data, 0, sizeof(eir_data));

    bdaddr_t addr;
    str2ba("C4:D9:87:C3:30:E3", &addr);

    // DO NOT DO THIS:
    // eir_data.services = g_slist_alloc(); // This create a first element in the list storing NULL

    // "%.8x-%.4x-%.4x-%.4x-%.8x%.4x"
    eir_data.services = g_slist_append(eir_data.services, "0000ffe5-0000-1000-8000-00805f9b34fb");
    eir_data.services = g_slist_append(eir_data.services, "12345678-9abc-def0-0fed-cba987654321");
    eir_data.name = "Natalya-FAKE-LED";
    printf("name      = %s\n",  eir_data.name);
    printf("len(name) = %zu\n", strlen(eir_data.name));

    //printf("NATALYA print name %s services %s", eir_data.name, (char *) eir_data.services->data);
    g_slist_foreach(eir_data.services, print_iterator, "-->");

    gpointer buffer = NULL;
    size_t buffer_size = 0;
    buffer = to_eir(&eir_data, buffer, &buffer_size);
    printf("EIR ready: @ = %p size = %zu\n", buffer, buffer_size);

    update_found_devices(NULL,
            &addr,
            0, -55,
            false, true,
            false,
            buffer, buffer_size);

    return 0;
}
