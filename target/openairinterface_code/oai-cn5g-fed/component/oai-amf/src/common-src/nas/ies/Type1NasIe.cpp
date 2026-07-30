/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "Type1NasIe.hpp"

#include "3gpp_24.501.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
Type1NasIe::Type1NasIe() : NasIe(), high_pos_(false), value_(0) {
  iei_ = std::nullopt;
}

//------------------------------------------------------------------------------
Type1NasIe::Type1NasIe(bool high_pos, uint8_t value) {
  iei_      = std::nullopt;
  high_pos_ = high_pos;
  value_    = value & 0x0f;
}

//------------------------------------------------------------------------------
Type1NasIe::Type1NasIe(bool high_pos) : value_() {
  iei_      = std::nullopt;
  high_pos_ = high_pos;
}

//------------------------------------------------------------------------------
Type1NasIe::Type1NasIe(uint8_t iei, uint8_t value) : NasIe() {
  iei_      = std::optional<uint8_t>(iei & 0x0f);
  high_pos_ = false;
  value_    = value & 0x0f;
}

//------------------------------------------------------------------------------
Type1NasIe::Type1NasIe(uint8_t iei) : NasIe(), value_() {
  iei_      = std::optional<uint8_t>(iei & 0x0f);
  high_pos_ = false;
}

//------------------------------------------------------------------------------
Type1NasIe::~Type1NasIe() {}

//------------------------------------------------------------------------------
void Type1NasIe::Set(bool high_pos, uint8_t value) {
  high_pos_ = high_pos;
  value_    = value & 0x0f;
}

//------------------------------------------------------------------------------
void Type1NasIe::Set(bool high_pos) {
  high_pos_ = high_pos;
}

//------------------------------------------------------------------------------
bool Type1NasIe::Validate(int len) const {
  if (len < kType1NasIeLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kType1NasIeLength);
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
uint32_t Type1NasIe::GetIeLength() const {
  if (iei_.has_value())
    return kType1NasIeLength;
  else
    return 0;
}

//------------------------------------------------------------------------------
void Type1NasIe::SetValue(uint8_t value) {
  value_ = value & 0x0f;  // 4 lower bits
}

//------------------------------------------------------------------------------
int Type1NasIe::Encode(uint8_t* buf, int len) const {
  if (!Validate(len)) return KEncodeDecodeError;

  int encoded_size = 0;
  uint8_t octet    = 0;
  if (iei_.has_value()) {
    octet = (iei_.value() << 4) | value_;
  } else {
    int decoded_size = 0;
    // First get value of this octet
    DECODE_U8(buf + encoded_size, octet, decoded_size);
    if (high_pos_) {
      octet =
          (octet & 0x0f) | (value_ << 4);  // Keep 4 less significant bits and
                                           // update 4 most significant bits
    } else {
      octet = (octet & 0xf0) | (value_);  // Keep 4 most significant bits and
                                          // update 4 less significant bits
    }
  }

  ENCODE_U8(buf + encoded_size, octet, encoded_size);

  if (iei_.has_value()) {
    return encoded_size;  // 1 octet
  } else {
    return 0;  // 1/2 octet
  }
}

//------------------------------------------------------------------------------
int Type1NasIe::Decode(const uint8_t* const buf, int len, bool is_iei) {
  return Decode(buf, len, false, is_iei);
}

//------------------------------------------------------------------------------
int Type1NasIe::Decode(
    const uint8_t* const buf, int len, bool high_pos, bool is_iei) {
  if (!Validate(len)) return KEncodeDecodeError;

  high_pos_        = high_pos;
  int decoded_size = 0;
  uint8_t octet    = 0;
  DECODE_U8(buf + decoded_size, octet, decoded_size);

  if (is_iei) {
    iei_   = std::optional<uint8_t>((octet & 0xf0) >> 4);
    value_ = octet & 0x0f;
  } else {
    if (high_pos_) {
      value_ = (octet & 0xf0) >> 4;
    } else {
      value_ = (octet & 0x0f);
    }
  }

  GetValue();  // Update value in the derived classes
  if (is_iei) {
    return decoded_size;  // 1 octet
  } else {
    return 0;  // 1/2 octet
  }
}
