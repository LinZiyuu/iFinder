/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "Type1NasIeFormatTv.hpp"

#include "3gpp_24.501.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"

using namespace oai::nas;
//------------------------------------------------------------------------------
Type1NasIeFormatTv::Type1NasIeFormatTv() : NasIe(), value_(0) {
  iei_ = std::nullopt;
}

//------------------------------------------------------------------------------
Type1NasIeFormatTv::Type1NasIeFormatTv(uint8_t iei) : NasIe(), value_(0) {
  iei_ = std::optional<uint8_t>(iei & 0x0f);
}

//------------------------------------------------------------------------------
Type1NasIeFormatTv::~Type1NasIeFormatTv() {}

//------------------------------------------------------------------------------
void Type1NasIeFormatTv::SetIei(uint8_t iei) {
  iei_ = std::optional<uint8_t>(iei & 0x0f);
}

//------------------------------------------------------------------------------
bool Type1NasIeFormatTv::Validate(int len) const {
  if (len < kType1NasIeFormatTvLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kType1NasIeFormatTvLength);
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
uint32_t Type1NasIeFormatTv::GetIeLength() const {
  if (iei_.has_value())
    return kType1NasIeFormatTvLength;
  else
    return 0;
}

//------------------------------------------------------------------------------
void Type1NasIeFormatTv::SetValue(uint8_t value) {
  value_ = value & 0x0f;  // 4 lower bits
}

//------------------------------------------------------------------------------
uint8_t Type1NasIeFormatTv::GetValue() const {
  return value_;
}

//------------------------------------------------------------------------------
int Type1NasIeFormatTv::Encode(uint8_t* buf, int len) const {
  if (!Validate(len)) return KEncodeDecodeError;

  int encoded_size = 0;
  uint8_t octet    = 0;
  if (iei_.has_value()) {
    octet = (iei_.value() << 4) | value_;
  } else {
    octet = value_ & 0x0f;
  }
  ENCODE_U8(buf + encoded_size, octet, encoded_size);

  if (iei_.has_value()) {
    oai::logger::logger_common::nas().debug(
        "Encoded Type1NasIeFormatTv, len (%d)", encoded_size);
    return encoded_size;  // 1 octet
  } else {
    oai::logger::logger_common::nas().debug("Encoded Type1NasIeFormatTv len 0");
    return 0;  // 1/2 octet
  }
}

//------------------------------------------------------------------------------
int Type1NasIeFormatTv::Decode(const uint8_t* const buf, int len, bool is_iei) {
  if (!Validate(len)) return KEncodeDecodeError;

  int decoded_size = 0;
  uint8_t octet    = 0;
  DECODE_U8(buf + decoded_size, octet, decoded_size);
  if (is_iei) {
    iei_ = std::optional<uint8_t>((octet & 0xf0) >> 4);
  }
  value_ = octet & 0x0f;

  if (is_iei) {
    return decoded_size;  // 1 octet
  } else {
    return 0;  // 1/2 octet
  }
}
