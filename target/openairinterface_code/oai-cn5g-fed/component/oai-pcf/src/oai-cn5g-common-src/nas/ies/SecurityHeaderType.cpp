/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "SecurityHeaderType.hpp"

#include "3gpp_24.501.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
SecurityHeaderType::SecurityHeaderType() : NasIe() {
  spare_            = 0;
  secu_header_type_ = 0;
}

//------------------------------------------------------------------------------
SecurityHeaderType::SecurityHeaderType(uint8_t secu_header_type) : NasIe() {
  spare_            = 0;
  secu_header_type_ = 0x0f & secu_header_type;
}

//------------------------------------------------------------------------------
// SecurityHeaderType::~SecurityHeaderType() {}

//------------------------------------------------------------------------------
bool SecurityHeaderType::Validate(int len) const {
  if (len < kSecurityHeaderTypeLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kSecurityHeaderTypeLength);
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
uint32_t SecurityHeaderType::GetIeLength() const {
  return kSecurityHeaderTypeLength;
}

//------------------------------------------------------------------------------
void SecurityHeaderType::Set(uint8_t secu_header_type, uint8_t spare) {
  secu_header_type_ = 0x0f & secu_header_type;
  spare_            = spare & 0xf0;
}

//------------------------------------------------------------------------------
void SecurityHeaderType::Get(uint8_t& secu_header_type) const {
  secu_header_type = secu_header_type_ & 0x0f;
}

//------------------------------------------------------------------------------
uint8_t SecurityHeaderType::Get() const {
  return (secu_header_type_ & 0x0f);
}

//------------------------------------------------------------------------------
int SecurityHeaderType::Encode(uint8_t* buf, int len) const {
  if (!Validate(len)) return KEncodeDecodeError;
  uint8_t value         = (secu_header_type_ & 0x0f) | (spare_ & 0xf0);
  uint32_t encoded_size = 0;
  ENCODE_U8(buf, value, encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int SecurityHeaderType::Decode(const uint8_t* const buf, int len, bool is_iei) {
  if (!Validate(len)) return KEncodeDecodeError;
  uint8_t value         = 0;
  uint32_t decoded_size = 0;
  DECODE_U8(buf, value, decoded_size);
  secu_header_type_ = 0x0f & value;
  spare_            = value & 0xf0;

  return decoded_size;
}
