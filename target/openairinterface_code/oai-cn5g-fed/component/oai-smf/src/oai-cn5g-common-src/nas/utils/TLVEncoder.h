/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_TLV_ENCODER_SEEN
#define FILE_TLV_ENCODER_SEEN

#include "bstrlib.h"
#include "common_defs.h"

#define IES_ENCODE_U8(buffer, encoded, value)                                  \
  ENCODE_U8(buffer + encoded, value, encoded)

#define IES_ENCODE_U16(buffer, encoded, value)                                 \
  ENCODE_U16(buffer + encoded, value, encoded)

#define IES_ENCODE_U24(buffer, encoded, value)                                 \
  ENCODE_U24(buffer + encoded, value, encoded)

#define IES_ENCODE_U32(buffer, encoded, value)                                 \
  ENCODE_U32(buffer + encoded, value, encoded)

/* Defines error code limit below which message should be sent because
 * it cannot be further processed */
#define TLV_FATAL_ERROR (TLV_VALUE_DOESNT_MATCH)

extern int errorCodeEncoder;

int encode_bstring(
    const_bstring const str, uint8_t* const buffer, const uint32_t buflen);

void tlv_encode_perror(void);

#define CHECK_PDU_POINTER_AND_LENGTH_ENCODER(bUFFER, mINIMUMlENGTH, lENGTH)    \
  if (bUFFER == NULL) {                                                        \
    errorCodeEncoder = TLV_BUFFER_NULL;                                        \
    return TLV_BUFFER_NULL;                                                    \
  }                                                                            \
  if (lENGTH < mINIMUMlENGTH) {                                                \
    errorCodeEncoder = TLV_BUFFER_TOO_SHORT;                                   \
    return TLV_BUFFER_TOO_SHORT;                                               \
  }

#define CHECK_PDU_POINTER_ENCODER(bUFFER)                                      \
  if (bUFFER == NULL) {                                                        \
    errorCodeEncoder = TLV_BUFFER_NULL;                                        \
    return TLV_BUFFER_NULL;                                                    \
  }

#endif /* define (FILE_TLV_ENCODER_SEEN) */
