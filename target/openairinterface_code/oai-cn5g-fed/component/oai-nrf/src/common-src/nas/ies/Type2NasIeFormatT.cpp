/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "Type2NasIeFormatT.hpp"

#include "3gpp_24.501.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"

using namespace oai::nas;
//------------------------------------------------------------------------------
Type2NasIeFormatT::Type2NasIeFormatT() : NasIe() {
  iei_ = 0;
}

//------------------------------------------------------------------------------
Type2NasIeFormatT::Type2NasIeFormatT(uint8_t iei) : NasIe() {
  iei_ = iei;
}

//------------------------------------------------------------------------------
Type2NasIeFormatT::~Type2NasIeFormatT() {}

//------------------------------------------------------------------------------
bool Type2NasIeFormatT::Validate(int len) const {
  if (len < kType2NasIeFormatTLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kType2NasIeFormatTLength);
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
uint32_t Type2NasIeFormatT::GetIeLength() const {
  return kType2NasIeFormatTLength;
}

//------------------------------------------------------------------------------
int Type2NasIeFormatT::Encode(uint8_t* buf, int len) const {
  if (!Validate(len)) return KEncodeDecodeError;

  int encoded_size = 0;
  ENCODE_U8(buf + encoded_size, iei_, encoded_size);

  return encoded_size;  // 1 octet
}

//------------------------------------------------------------------------------
int Type2NasIeFormatT::Decode(const uint8_t* const buf, int len, bool is_iei) {
  if (!Validate(len)) return KEncodeDecodeError;

  int decoded_size = 0;
  DECODE_U8(buf + decoded_size, iei_, decoded_size);

  return decoded_size;  // 1 octet
}
