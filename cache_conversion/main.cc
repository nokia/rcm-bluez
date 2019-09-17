#include "string.h"
#include "stdio.h"
#include "sys/stat.h"
#include "stdint.h"
#include "stdbool.h"
#include "stdlib.h"
#include <arpa/inet.h>
#include <inttypes.h>

#define FROM_CACHE "path_to_bluez_cache/F8:1D:78:60:3D:D9"	// For info only, please use your address
#define FROM_CACHE_C4 "path_to_bluez_cache/C4:BE:84:45:90:9E"

enum {
  BTA_GATTC_ATTR_TYPE_INCL_SRVC,
  BTA_GATTC_ATTR_TYPE_CHAR,
  BTA_GATTC_ATTR_TYPE_CHAR_DESCR,
  BTA_GATTC_ATTR_TYPE_SRVC
};
typedef uint8_t tBTA_GATTC_ATTR_TYPE;

typedef struct {
#define LEN_UUID_16 2
#define LEN_UUID_32 4
#define LEN_UUID_128 16

  uint16_t len;

  union {
    uint16_t uuid16;
    uint32_t uuid32;
    uint8_t uuid128[16];
  } uu;

} tBT_UUID;

typedef struct {
  tBT_UUID uuid;
  uint16_t s_handle;
  uint16_t e_handle; /* used for service only */
  uint8_t attr_type;
  uint8_t id;
  uint8_t prop;              /* used when attribute type is characteristic */
  bool is_primary;           /* used when attribute type is service */
  uint16_t incl_srvc_handle; /* used when attribute type is included service */
} tBTA_GATTC_NV_ATTR;

/**
 * hex2int
 * take a hex string and convert it to a 32bit number (max 8 hex digits)
 */
uint32_t hex2int(char *hex) {
    uint32_t val = 0;
    while (*hex) {
        // get current character then increment
        uint8_t byte = *hex++; 
        // transform hex character to the 4bit equivalent number, using the ascii table indexes
        if (byte >= '0' && byte <= '9') byte = byte - '0';
        else if (byte >= 'a' && byte <='f') byte = byte - 'a' + 10;
        else if (byte >= 'A' && byte <='F') byte = byte - 'A' + 10;    
        // shift 4 to make space for new digit, and add the 4 bits of the new digit 
        val = (val << 4) | (byte & 0xF);
    }
    return val;
}

void parse_hex_string(const char *hexstring, uint8_t *buffer){
	const char *s = hexstring;
	size_t n = strlen(hexstring) / 2;
	for(size_t i=0; i<n; ++i, buffer += 1, s+= 2)
		sscanf(s, "%2x", buffer);
}

void parse_attribute(	char *line, 
			tBTA_GATTC_NV_ATTR *attr, 
			char *uuid_buf){

   char *copy = line;
   char delimiters[] = "=:-";
   int uuid_buf_pos = 0;
   int count = 1;
   char *token;

// initialize some attribute features
   attr->id = 0;
   attr->prop = 0;
   attr->e_handle = 0;
   attr->is_primary = false;
   attr->incl_srvc_handle = 0;

   token = strsep(&copy, delimiters);
   while(token != NULL){
	if(count == 1){
	   attr->s_handle = (uint16_t)strtol(token, NULL, 16);
	}
	if(count == 2){
	   if(strcmp(token, "2800") == 0){
		printf("The attribute is a service\n");
		attr->attr_type = BTA_GATTC_ATTR_TYPE_SRVC;
		attr->is_primary = true;
	   }
	   else if(strcmp(token, "2803") == 0){
		printf("The attribute is a characteristic\n");
		attr->attr_type = BTA_GATTC_ATTR_TYPE_CHAR;
	   }
	   else{
		printf("The attribute is a descriptor\n");
		attr->attr_type = BTA_GATTC_ATTR_TYPE_CHAR_DESCR;
		sprintf(&uuid_buf[uuid_buf_pos], "%s", token);
		uuid_buf_pos += strlen(token);
	   }
	}
	if(count == 3){
		if(attr->attr_type == BTA_GATTC_ATTR_TYPE_SRVC)
		   attr->e_handle = (uint16_t)strtol(token, NULL, 16);
		else if(attr->attr_type == BTA_GATTC_ATTR_TYPE_CHAR_DESCR){
			sprintf(&uuid_buf[uuid_buf_pos], "%s", token);
                       	uuid_buf_pos += strlen(token);
		}
	}
	if(count == 4){
		if(attr->attr_type == BTA_GATTC_ATTR_TYPE_CHAR){
			attr->prop = (uint8_t)strtol(token, NULL, 16);
		}
		else if(attr->attr_type == BTA_GATTC_ATTR_TYPE_SRVC ||
		   attr->attr_type == BTA_GATTC_ATTR_TYPE_CHAR_DESCR){
			sprintf(&uuid_buf[uuid_buf_pos], "%s", token);
			uuid_buf_pos += strlen(token);
		}
	}
	if(count >= 5){
		int len = strlen(token);
		if(token[len-1] == '\n'){
		// end of attribute, do not copy the end of line character
			len = len - 1;
		}
		memcpy(&uuid_buf[uuid_buf_pos], token, len);
		uuid_buf_pos += len;
	}
	count++;
	token = strsep(&copy, delimiters);
   }
   printf("End of line\n");
   printf("uuid buffer pos = %d\n", uuid_buf_pos);
   uuid_buf[uuid_buf_pos] = '\0';
}

void print_hex(size_t len, void *p){
        uint8_t *q = (uint8_t*)p;
        for(int i=0; i<len; i++){
                printf("%02hhx ", *q++);
                if(i % 32 == 31)
                        printf("\n");
        }
        printf("\n");
}

int main(){

	FILE *from_fd = fopen(FROM_CACHE, "rb");
	FILE *to_fd = fopen("output_for_android_cache/gatt_cache_C4BE8445909E", "wb");
	if(!from_fd || !to_fd){
	   printf("Error opening file\n");
	   return 1;
	}
	struct stat file_stat;
	if(stat(FROM_CACHE, &file_stat) < 0){
	   printf("Error getting file stats\n");
	   fclose(from_fd);
	   fclose(to_fd);
	   return 1;
	}

	printf("File size = %d\n", file_stat.st_size);
	const int to_size = file_stat.st_size;
	uint8_t buffer[to_size];
	char line[2048];
	int num_attr = 0;
	int buf_pos = 0;
	bool start = false;
	int pos = 0;

	while(fgets(line, 2048, from_fd) != NULL){
		printf("pos=%d\n", pos);
	   if(!start){
	      if(strncmp(line, "[Attributes]", 12) == 0){
	         start = true;
	      }
	   }else{
		   printf("--------------------------------\n");
		   printf("Attribute found: %s", line);
		   num_attr++;
  		   char uuid_buf[32];
	  	   tBTA_GATTC_NV_ATTR *attr = (tBTA_GATTC_NV_ATTR*)malloc(sizeof(tBTA_GATTC_NV_ATTR));

	   	   // parse the current attribute string
	   	   parse_attribute(line, attr, uuid_buf);

	   printf("attr structure:\n\t uuid_len: %d uuid: %lx\n\t", attr->uuid.len, attr->uuid.uu);
	   printf("s_handle: %d, e_handle: %d\n\t", attr->s_handle, attr->e_handle);
	   printf("attr_type: %d id: %d\n\t", attr->attr_type, attr->id);
	   printf("prop: %d primary: %d\n\t", attr->prop, attr->is_primary);
	   printf("incl_srvc_handle: %d\n", attr->incl_srvc_handle);

		   uint16_t len = (uint16_t)sizeof(uuid_buf)/sizeof(uuid_buf[0]);
	   	   attr->uuid.len = (uint16_t)len/2;
	   	   printf("string UUID = %s len = %d uuid_buf[31]=%c uuid_buf[32]=%c\n", uuid_buf, len, uuid_buf[31], uuid_buf[32]);

		   // Transform char uuid to hex and copy to attr.uuid.uu.uuid128
	   	   const char *uuid = uuid_buf;
	   	   uint8_t *temp_buf_uuid128 = attr->uuid.uu.uuid128;
		   size_t n = strlen(uuid_buf)/2;

		   for(size_t i=0; i < attr->uuid.len; i++, temp_buf_uuid128 += 1, uuid += 2){
                        printf("uuid = %s\n", uuid);
                        sscanf(uuid, "%02hhx", temp_buf_uuid128);
                   }

//		   memcpy(attr->uuid.uu.uuid128, ntohs(attr->uuid.uu.uuid128), attr->uuid.len);

// start uuid16 returned
/*
   	   	   uint8_t *temp_buf_uuid16 = (uint8_t *)(&attr->uuid.uu.uuid16);
		   char uuid16_str[5];
		   memcpy(uuid16_str, &uuid_buf[4], 4);
	   	   const char *uuid = uuid16_str;
		   uuid16_str[4] = '\0';
		   printf("uuid16_str = %s uuid = %s\n", uuid16_str, uuid);

		   attr->uuid.len = (uint16_t)strlen(uuid16_str)/2;
		   for(size_t i=0; i < attr->uuid.len; i++, temp_buf_uuid16 += 1, uuid += 2){
			printf("uuid = %s\n", uuid);
			sscanf(uuid, "%02hhx", temp_buf_uuid16);
			printf("uuid16_len = %d uuid16_str[%d] = %s temp_buf = %02x\n", attr->uuid.len, i, uuid, attr->uuid.uu.uuid16);
		   }
		   printf("before htons = %d\n", attr->uuid.uu.uuid16);
		   attr->uuid.uu.uuid16 = ntohs(attr->uuid.uu.uuid16);
		   printf("after htons = %d\n", attr->uuid.uu.uuid16);
		   print_hex(attr->uuid.len, &attr->uuid.uu);
*/
// end
/*
		   for(size_t i=0; i<n; i++, temp_buf += 1, uuid += 2){
			sscanf(uuid, "%02hhx", temp_buf);
//			printf("uuid[%d] = %s temp_buf = %02x\n", i, uuid, attr->uuid.uu.uuid128[i]);
		   }
*/
//	printf("test uuid buffer, sizeof = %d\n", sizeof(tBT_UUID));

		   memcpy(buffer+pos, attr, sizeof(tBTA_GATTC_NV_ATTR));
		   pos += sizeof(tBTA_GATTC_NV_ATTR);

	printf("buffer: \n");
        print_hex(pos, buffer);
/*
	for(int i=0; i<pos; i++)
		printf("%02x ", buffer[i]);
	printf("\n");
*/

 		   printf("hex: ");
	   	   for(int i=0; i<16; i++)
		   	printf("%02x ", attr->uuid.uu.uuid128[i]);
	   	   printf("\n");
	   	   printf("--------------------------------\n");

		   free(attr);
	   } // else
	} // while
	fclose(from_fd); // don't need it anymore

	// buffer length 
	size_t buf_len = num_attr * (sizeof(tBTA_GATTC_NV_ATTR));
	printf("sizeof(buffer) = %d buf_len = %d sizeof(tBTA_GATTC_NV_ATTR) = %d\n",
		sizeof(buffer), buf_len, sizeof(tBTA_GATTC_NV_ATTR));
	for(int i=0; i<buf_len; i++)
		printf("%02x ", buffer[i]);
	printf("\n");

	uint16_t cache_ver = 2;
	if(fwrite(&cache_ver, sizeof(uint16_t), 1, to_fd) != 1){
		printf("Can't write cache_ver in file\n");
		fclose(to_fd);
	}
	if(fwrite(&num_attr, sizeof(uint16_t), 1, to_fd) != 1){
		printf("Can't write num_attr in file\n");
		fclose(to_fd);
	}
	if(fwrite(buffer, buf_len, 1, to_fd) != 1){
		printf("Can't write attr in file\n");
		fclose(to_fd);
	}

//	uint16_t cache_ver = 2;
//	memcpy(buffer, &cache_ver, 2);
//	pos += 2;

//	fclose(from_fd);
	fclose(to_fd);

	return 0;
}
