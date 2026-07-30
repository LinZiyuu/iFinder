/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "Type1NasIeFormatV.hpp"

#include "3gpp_24.501.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
Type1NasIeFormatV::Type1NasIeFormatV() : NasIe(), high_pos_(false), value_(0) {}

//------------------------------------------------------------------------------
Type1NasIeFormatV::Type1NasIeFormatV(bool high_pos) : NasIe(), value_(0) {
  high_pos_ = high_pos;
}

//------------------------------------------------------------------------------
Type1NasIeFormatV::Type1NasIeFormatV(bool high_pos, uint8_t value) : NasIe() {
  high_pos_ = high_pos;
  value_    = value & 0x0f;
}

//------------------------------------------------------------------------------
Type1NasIeFormatV::~Type1NasIeFormatV() {}

//------------------------------------------------------------------------------
bool Type1NasIeFormatV::Validate(int len) const {
  if (len < kType1NasIeFormatVLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kType1NasIeFormatVLength);
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
uint32_t Type1NasIeFormatV::GetIeLength() const {
  return kType1NasIeFormatVLength;
}

//------------------------------------------------------------------------------
void Type1NasIeFormatV::Set(bool high_pos, uint8_t value) {
  high_pos_ = high_pos;
  value_    = value & 0x0f;  // 4 bits
}

//------------------------------------------------------------------------------
void Type1NasIeFormatV::Set(uint8_t value) {
  value_ = value & 0x0f;  // 4 bits
}

//------------------------------------------------------------------------------
int Type1NasIeFormatV::Encode(uint8_t* buf, int len) const {
  if (!Validate(len)) return KEncodeDecodeError;

  int encoded_size = 0;
  int decoded_size = 0;
  uint8_t octet    = 0;

  // First get value of this octet
  DECODE_U8(buf + encoded_size, octet, decoded_size);
  if (high_pos_) {
    octet = (octet & 0x0f) | (value_ << 4);  // Keep 4 less significant bits and
                                             // update 4 most significant bits
  } else {
    octet = (octet & 0xf0) | (value_);  // Keep 4 most significant bits and
                                        // update 4 less significant bits
  }

  ENCODE_U8(buf + encoded_size, octet, encoded_size);

  return 0;  // 1/2 octet
}

//------------------------------------------------------------------------------
int Type1NasIeFormatV::Decode(
    const uint8_t* const buf, int len, bool high_pos) {
  if (!Validate(len)) return KEncodeDecodeError;
  high_pos_        = high_pos;
  int decoded_size = 0;
  uint8_t octet    = 0;
  DECODE_U8(buf + decoded_size, octet, decoded_size);

  if (high_pos_) {
    value_ = (octet & 0xf0) >> 4;
  } else {
    value_ = (octet & 0x0f);
  }
  return 0;  // 1/2 octet
}
