/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "NasMessageType.hpp"

#include "3gpp_24.501.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
NasMessageType::NasMessageType(uint8_t message_type)
    : NasIe(), message_type_(message_type) {}

//------------------------------------------------------------------------------
// NasMessageType::~NasMessageType() {}

//------------------------------------------------------------------------------
bool NasMessageType::Validate(int len) const {
  if (len < kNasMessageTypeIeSize) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kNasMessageTypeIeSize);
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
uint32_t NasMessageType::GetIeLength() const {
  return kNasMessageTypeIeSize;
}

//------------------------------------------------------------------------------
void NasMessageType::Set(uint8_t message_type) {
  message_type_ = message_type;
}

//------------------------------------------------------------------------------
void NasMessageType::Get(uint8_t& message_type) const {
  message_type = message_type_;
}

//------------------------------------------------------------------------------
uint8_t NasMessageType::Get() const {
  return message_type_;
}

//------------------------------------------------------------------------------
int NasMessageType::Encode(uint8_t* buf, int len) const {
  if (!Validate(len)) return KEncodeDecodeError;

  uint32_t encoded_size = 0;
  ENCODE_U8(buf, message_type_, encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int NasMessageType::Decode(const uint8_t* const buf, int len, bool is_iei) {
  if (!Validate(len)) return KEncodeDecodeError;
  uint32_t decoded_size = 0;
  DECODE_U8(buf, message_type_, decoded_size);
  return decoded_size;
}
