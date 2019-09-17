#include <errno.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <glib.h>

//--------------------------------------------------------------------------
// EIR crafting
//--------------------------------------------------------------------------

void to_eir_GSList_cb_write_uint128(gpointer item, gpointer pbuffer) {
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

void to_eir_string_write(gpointer item, gpointer pbuffer) {
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

gpointer to_eir(const struct eir_data * eir_data, gpointer buffer, uint16_t *pbuffer_size) {
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
            printf("enlarge buffer %zu > %zu\n", (size_t) eir_size, (size_t) *pbuffer_size);
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
