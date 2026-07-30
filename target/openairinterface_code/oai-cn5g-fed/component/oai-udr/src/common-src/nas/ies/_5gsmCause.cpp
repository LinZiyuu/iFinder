/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "_5gsmCause.hpp"

#include "3gpp_24.501.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"
using namespace oai::nas;

//------------------------------------------------------------------------------
_5gsmCause::_5gsmCause(uint8_t iei) : Type3NasIe(kIei5gsmCause) {
  value_ = 0;
}

//------------------------------------------------------------------------------
_5gsmCause::_5gsmCause() : Type3NasIe() {
  value_ = 0;
}

//------------------------------------------------------------------------------
_5gsmCause::_5gsmCause(uint8_t iei, uint8_t value) : Type3NasIe(iei) {
  value_ = value;
}

//------------------------------------------------------------------------------
//_5gsmCause::~_5gsmCause(){};

//------------------------------------------------------------------------------
uint32_t _5gsmCause::GetIeLength() const {
  return (k5gsmCauseMaximumLength - 1 + Type3NasIe::GetIeLength());
}

//------------------------------------------------------------------------------
void _5gsmCause::SetValue(uint8_t value) {
  value_ = value;
}

//------------------------------------------------------------------------------
uint8_t _5gsmCause::GetValue() const {
  return value_;
}

//------------------------------------------------------------------------------
void _5gsmCause::Set(uint8_t iei, uint8_t value) {
  SetIei(iei);
  value_ = value;
}

//------------------------------------------------------------------------------
int _5gsmCause::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());

  if (len < k5gsmCauseMinimumLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        k5gsmCauseMinimumLength);
    return KEncodeDecodeError;
  }
  int encoded_size = 0;

  // IEI
  encoded_size += Type3NasIe::Encode(buf + encoded_size, len);
  // Value
  ENCODE_U8(buf + encoded_size, value_, encoded_size);

  oai::logger::logger_common::nas().debug(
      "Encoded %s, len (%d)", GetIeName().c_str(), encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int _5gsmCause::Decode(const uint8_t* const buf, int len, bool is_iei) {
  oai::logger::logger_common::nas().debug("Decoding %s", GetIeName().c_str());

  if (len < k5gsmCauseMinimumLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        k5gsmCauseMinimumLength);
    return KEncodeDecodeError;
  }

  int decoded_size = 0;
  // IEI and Length
  decoded_size += Type3NasIe::Decode(buf + decoded_size, len, is_iei);

  DECODE_U8(buf + decoded_size, value_, decoded_size);

  oai::logger::logger_common::nas().debug("Decoded value 0x%x", value_);
  oai::logger::logger_common::nas().debug(
      "Decoded %s, len (%d)", GetIeName().c_str(), decoded_size);
  return decoded_size;
}
