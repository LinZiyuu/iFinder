/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "Type3NasIe.hpp"

#include "3gpp_24.501.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
Type3NasIe::Type3NasIe() : NasIe() {
  iei_ = std::nullopt;
}

//------------------------------------------------------------------------------
Type3NasIe::Type3NasIe(uint8_t iei) : NasIe() {
  iei_ = std::optional<uint8_t>(iei);
}

//------------------------------------------------------------------------------
// Type3NasIe::~Type3NasIe() {}

//------------------------------------------------------------------------------
void Type3NasIe::SetIei(uint8_t iei) {
  iei_ = std::optional<uint8_t>(iei);
}

//------------------------------------------------------------------------------
bool Type3NasIe::Validate(int len) const {
  if (iei_.has_value() and (len < kType3NasIeFormatTvLength)) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kType3NasIeFormatTvLength);
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
uint32_t Type3NasIe::GetIeLength() const {
  if (iei_.has_value()) {
    return kType3NasIeFormatTvLength;
  } else {
    return kType3NasIeFormatTvLength - 1;
  }
}

//------------------------------------------------------------------------------
int Type3NasIe::Encode(uint8_t* buf, int len) const {
  if (!Validate(len)) return KEncodeDecodeError;

  int encoded_size = 0;
  uint8_t octet    = 0;
  if (iei_.has_value()) {
    ENCODE_U8(buf + encoded_size, iei_.value(), encoded_size);
  }
  return encoded_size;
}

//------------------------------------------------------------------------------
int Type3NasIe::Decode(const uint8_t* const buf, int len, bool is_iei) {
  if (!Validate(len)) return KEncodeDecodeError;

  int decoded_size = 0;
  uint8_t octet    = 0;

  if (is_iei) {
    DECODE_U8(buf + decoded_size, octet, decoded_size);
    iei_ = std::optional<uint8_t>(octet);
  }
  return decoded_size;
}
