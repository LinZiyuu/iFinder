/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_COMMON_DEFS_SEEN
#define FILE_COMMON_DEFS_SEEN

#include <arpa/inet.h>
#include <stdint.h>

typedef enum {
  RETURNerror = -1,
  RETURNok    = 0,
  // RETURNclear = 2
} status_code_e;

typedef enum {
  /* Fatal errors - received message should not be processed */
  TLV_MAC_MISMATCH                  = -14,
  TLV_BUFFER_NULL                   = -13,
  TLV_BUFFER_TOO_SHORT              = -12,
  TLV_PROTOCOL_NOT_SUPPORTED        = -11,
  TLV_WRONG_MESSAGE_TYPE            = -10,
  TLV_OCTET_STRING_TOO_LONG_FOR_IEI = -9,

  TLV_VALUE_DOESNT_MATCH          = -4,
  TLV_MANDATORY_FIELD_NOT_PRESENT = -3,
  TLV_UNEXPECTED_IEI              = -2,

  //  RETURNerror                             = -1,
  //  RETURNok                                = 0,

  TLV_ERROR_OK = RETURNok,
  /* Defines error code limit below which received message should be discarded
   * because it cannot be further processed */
  TLV_FATAL_ERROR = TLV_VALUE_DOESNT_MATCH

} error_code_e;

//------------------------------------------------------------------------------
#define DECODE_U8_VALUE(bUFFER, vALUE, oFFSET, sIZE)                           \
  if (oFFSET < sIZE) {                                                         \
    vALUE = *(uint8_t*) (bUFFER + oFFSET);                                     \
  } else {                                                                     \
    vALUE = 0x00;                                                              \
  }

#define DECODE_U8(bUFFER, vALUE, sIZE)                                         \
  vALUE = *(uint8_t*) (bUFFER);                                                \
  sIZE += sizeof(uint8_t)

#define DECODE_U16(bUFFER, vALUE, sIZE)                                        \
  vALUE = ntohs(*(uint16_t*) (bUFFER));                                        \
  sIZE += sizeof(uint16_t)

#define DECODE_U24(bUFFER, vALUE, sIZE)                                        \
  do {                                                                         \
    uint32_t value_tmp = 0;                                                    \
    uint8_t size_tmp   = sizeof(uint8_t) + sizeof(uint16_t);                   \
    memcpy((unsigned char*) &value_tmp, bUFFER, size_tmp);                     \
    vALUE = ntohl(value_tmp);                                                  \
    vALUE = vALUE >> 8;                                                        \
    sIZE += size_tmp;                                                          \
  } while (0)

#define DECODE_U32(bUFFER, vALUE, sIZE)                                        \
  vALUE = ntohl(*(uint32_t*) (bUFFER));                                        \
  sIZE += sizeof(uint32_t)

#if (BYTE_ORDER == LITTLE_ENDIAN)
#define DECODE_LENGTH_U16(bUFFER, vALUE, sIZE)                                 \
  vALUE = ((*(bUFFER)) << 8) | (*((bUFFER) + 1));                              \
  sIZE += sizeof(uint16_t)
#else
#define DECODE_LENGTH_U16(bUFFER, vALUE, sIZE)                                 \
  vALUE = (*(bUFFER)) | (*((bUFFER) + 1) << 8);                                \
  sIZE += sizeof(uint16_t)
#endif

#define ENCODE_U8(buffer, value, size)                                         \
  *(uint8_t*) (buffer) = value;                                                \
  size += sizeof(uint8_t)

#define ENCODE_U16(buffer, value, size)                                        \
  *(uint16_t*) (buffer) = htons(value);                                        \
  size += sizeof(uint16_t)

#define ENCODE_U24(buffer, value, size)                                        \
  do {                                                                         \
    uint32_t value_tmp = htonl(value << 8);                                    \
    uint8_t size_tmp   = sizeof(uint8_t) + sizeof(uint16_t);                   \
    memcpy(buffer, (unsigned char*) &value_tmp, size_tmp);                     \
    size += size_tmp;                                                          \
  } while (0)

#define ENCODE_U32(buffer, value, size)                                        \
  *(uint32_t*) (buffer) = htonl(value);                                        \
  size += sizeof(uint32_t)

////////////
#define IPV4_STR_ADDR_TO_INADDR(AdDr_StR, InAdDr, MeSsAgE)                     \
  do {                                                                         \
    if (inet_aton(AdDr_StR, &InAdDr) <= 0) {                                   \
      throw(MeSsAgE);                                                          \
    }                                                                          \
  } while (0)

#ifndef UNUSED
#define UNUSED(x) (void) (x)
#endif

#endif /* FILE_COMMON_DEFS_SEEN */
