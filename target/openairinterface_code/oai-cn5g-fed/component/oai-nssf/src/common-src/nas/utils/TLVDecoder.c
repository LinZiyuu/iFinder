/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "TLVDecoder.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bstrlib.h"

int errorCodeDecoder = 0;

//------------------------------------------------------------------------------
int decode_bstring(
    bstring* bstr, const uint16_t pdulen, const uint8_t* const buffer,
    const uint32_t buflen) {
  if (buflen < pdulen) {
    return TLV_BUFFER_TOO_SHORT;
  }

  if ((bstr) && (buffer)) {
    *bstr = blk2bstr(buffer, pdulen);
    return pdulen;
  } else {
    *bstr = NULL;
    return TLV_BUFFER_TOO_SHORT;
  }
}

//------------------------------------------------------------------------------
bstring dump_bstring_xml(const bstring bstr) {
  if (bstr) {
    int i;

    bstring b = bformat("<Length>%u</Length>\n\t<values>", bstr->slen);
    for (i = 0; i < bstr->slen; i++) {
      bformata(b, "0x%x ", bstr->data[i]);
    }
    bcatcstr(b, "</values>\n");
    return b;
  } else {
    bstring b = bfromcstr("<Length>0</Length>\n");
    return b;
  }
}
