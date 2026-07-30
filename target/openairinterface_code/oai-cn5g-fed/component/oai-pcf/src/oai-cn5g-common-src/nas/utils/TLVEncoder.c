/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "TLVEncoder.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int errorCodeEncoder = 0;

int encode_bstring(
    const_bstring const str, uint8_t* const buffer, const uint32_t buflen) {
  if (str) {
    if (blength(str) > 0) {
      CHECK_PDU_POINTER_AND_LENGTH_ENCODER(buffer, blength(str), buflen);
      memcpy((void*) buffer, (void*) str->data, blength(str));
      return blength(str);
    } else {
      return 0;
    }
  } else {
    return 0;
  }
}
