/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_TLV_DECODER_SEEN
#define FILE_TLV_DECODER_SEEN

#include "bstrlib.h"
#include "common_defs.h"

#define IES_DECODE_U8(bUFFER, dECODED, vALUE)                                  \
  DECODE_U8(bUFFER + dECODED, vALUE, dECODED)

#define IES_DECODE_U16(bUFFER, dECODED, vALUE)                                 \
  DECODE_U16(bUFFER + dECODED, vALUE, dECODED)

#define IES_DECODE_U24(bUFFER, dECODED, vALUE)                                 \
  DECODE_U24(bUFFER + dECODED, vALUE, dECODED)

#define IES_DECODE_U32(bUFFER, dECODED, vALUE)                                 \
  DECODE_U32(bUFFER + dECODED, vALUE, dECODED)

extern int errorCodeDecoder;

int decode_bstring(
    bstring* octetstring, const uint16_t pdulen, const uint8_t* const buffer,
    const uint32_t buflen);

bstring dump_bstring_xml(const bstring bstr);

void tlv_decode_perror(void);

#define CHECK_PDU_POINTER_AND_LENGTH_DECODER(bUFFER, mINIMUMlENGTH, lENGTH)    \
  if (bUFFER == NULL) {                                                        \
    errorCodeDecoder = TLV_BUFFER_NULL;                                        \
    return TLV_BUFFER_NULL;                                                    \
  }                                                                            \
  if (lENGTH < mINIMUMlENGTH) {                                                \
    errorCodeDecoder = TLV_BUFFER_TOO_SHORT;                                   \
    return TLV_BUFFER_TOO_SHORT;                                               \
  }

#define CHECK_LENGTH_DECODER(bUFFERlENGTH, lENGTH)                             \
  if (bUFFERlENGTH < lENGTH) {                                                 \
    errorCodeDecoder = TLV_BUFFER_TOO_SHORT;                                   \
    return TLV_BUFFER_TOO_SHORT;                                               \
  }

#define CHECK_MESSAGE_TYPE(mESSAGE_tYPE, bUFFER)                               \
  {                                                                            \
    if (mESSAGE_tYPE != bUFFER) {                                              \
      errorCodeDecoder = TLV_WRONG_MESSAGE_TYPE;                               \
      return errorCodeDecoder;                                                 \
    }                                                                          \
  }

#define CHECK_IEI_DECODER(iEI, bUFFER)                                         \
  if (iEI != bUFFER) {                                                         \
    errorCodeDecoder = TLV_UNEXPECTED_IEI;                                     \
    return TLV_UNEXPECTED_IEI;                                                 \
  }

#endif /* define (FILE_TLV_DECODER_SEEN) */
