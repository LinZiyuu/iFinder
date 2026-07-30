/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "nas_utils.hpp"

#include "3gpp_24.501.hpp"
#include "common_defs.hpp"
#include "common_defs.h"
#include "logger_base.hpp"
#include "utils.hpp"

#include <stdlib.h>

extern "C" {
#include "assertions.h"
#include "backtrace.h"
}

using namespace oai::nas;
//------------------------------------------------------------------------------
int nas_utils::encodeMccMnc2Buffer(
    const std::string& mcc_str, const std::string& mnc_str, uint8_t* buf,
    int len) {
  int encoded_size = 0;
  uint8_t value    = 0;
  int mcc          = oai::utils::utils::fromString<int>(mcc_str);
  int mnc          = oai::utils::utils::fromString<int>(mnc_str);

  // MCC digit 2, MCC digit 1
  value = (0x0f & (mcc / 100)) | ((0x0f & ((mcc % 100) / 10)) << 4);
  ENCODE_U8(buf + encoded_size, value, encoded_size);

  oai::logger::logger_common::nas().debug("MNC digit 1: %d", mnc / 100);
  if (!(mnc / 100)) {
    oai::logger::logger_common::nas().debug("Encoding MNC 2 digits");
    // bit 5-8 is coded as 1111, MCC digit 3
    value = (0x0f & (mcc % 10)) | 0xf0;
    ENCODE_U8(buf + encoded_size, value, encoded_size);

    // MNC digit 2, MNC digit 1
    value = (0x0f & ((mnc % 100) / 10)) | ((0x0f & (mnc % 10)) << 4);
    ENCODE_U8(buf + encoded_size, value, encoded_size);

  } else {
    oai::logger::logger_common::nas().debug("Encoding MNC 3 digits");
    // MNC digit 3, MCC digit 3
    value = (0x0f & (mcc % 10)) | ((0x0f & (mnc % 10)) << 4);
    ENCODE_U8(buf + encoded_size, value, encoded_size);

    // MNC digit 2, MNC digit 1
    value = ((0x0f & ((mnc % 100) / 10)) << 4) | (0x0f & (mnc / 100));
    ENCODE_U8(buf + encoded_size, value, encoded_size);
  }
  oai::logger::logger_common::nas().debug(
      "MCC %s, MNC %s", mcc_str.c_str(), mnc_str.c_str());
  return encoded_size;
}

//------------------------------------------------------------------------------
int nas_utils::decodeMccMncFromBuffer(
    std::string& mcc_str, std::string& mnc_str, const uint8_t* const buf,
    int len) {
  if (len < kMccMncLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kMccMncLength);
    return KEncodeDecodeError;
  }
  int decoded_size = 0;
  uint8_t octet    = 0;

  DECODE_U8(buf + decoded_size, octet, decoded_size);
  int mcc = 0;
  int mnc = 0;
  mcc += ((octet & 0x0f) * 100 + ((octet & 0xf0) >> 4) * 10);

  DECODE_U8(buf + decoded_size, octet, decoded_size);
  mcc += (octet & 0x0f);

  if ((octet & 0xf0) == 0xf0) {
    DECODE_U8(buf + decoded_size, octet, decoded_size);
    mnc += ((octet & 0x0f) * 10 + ((octet & 0xf0) >> 4));
    mnc_str = std::to_string(mnc);
    if (mnc < 10) {
      mnc_str = "0" + mnc_str;
    }
  } else {
    mnc += ((octet & 0xf0) >> 4);
    DECODE_U8(buf + decoded_size, octet, decoded_size);
    mnc += ((octet & 0x0f) * 100 + ((octet & 0xf0) >> 4) * 10);
    mnc_str = std::to_string(mnc);
    if (mnc < 10) {
      mnc_str = "00" + mnc_str;
    } else if (mnc < 100) {
      mnc_str = "0" + mnc_str;
    }
  }

  mcc_str = std::to_string(mcc);
  if (mcc < 10) {
    mcc_str = "00" + mcc_str;
  } else if (mcc < 100) {
    mcc_str = "0" + mcc_str;
  }

  oai::logger::logger_common::nas().debug(
      "MCC %s, MNC %s", mcc_str.c_str(), mnc_str.c_str());
  return decoded_size;
}
