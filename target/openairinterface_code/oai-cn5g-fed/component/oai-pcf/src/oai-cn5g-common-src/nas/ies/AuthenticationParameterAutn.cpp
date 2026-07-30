/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "AuthenticationParameterAutn.hpp"

#include "3gpp_24.501.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"
using namespace oai::nas;

//------------------------------------------------------------------------------
AuthenticationParameterAutn::AuthenticationParameterAutn(uint8_t iei)
    : Type4NasIe(iei), value_() {
  SetLengthIndicator(kAuthenticationParameterAutnValueLength);
}

//------------------------------------------------------------------------------
AuthenticationParameterAutn::AuthenticationParameterAutn(
    uint8_t iei, uint8_t value[kAuthenticationParameterAutnValueLength])
    : Type4NasIe(iei) {
  for (int i = 0; i < kAuthenticationParameterAutnValueLength; i++) {
    this->value_[i] = value[i];
  }
  SetLengthIndicator(kAuthenticationParameterAutnValueLength);
}

//------------------------------------------------------------------------------
AuthenticationParameterAutn::AuthenticationParameterAutn()
    : Type4NasIe(), value_() {
  SetLengthIndicator(kAuthenticationParameterAutnValueLength);
}

//------------------------------------------------------------------------------
AuthenticationParameterAutn::~AuthenticationParameterAutn() {}

//------------------------------------------------------------------------------
int AuthenticationParameterAutn::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());

  int encoded_size = 0;
  // Validate the buffer's length and Encode IEI/Length
  int encoded_header_size = Type4NasIe::Encode(buf + encoded_size, len);
  if (encoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  encoded_size += encoded_header_size;

  if (GetLengthIndicator() != kAuthenticationParameterAutnValueLength)
    return KEncodeDecodeError;

  for (int i = 0; i < kAuthenticationParameterAutnValueLength; i++) {
    ENCODE_U8(buf + encoded_size, value_[i], encoded_size);
  }

  oai::logger::logger_common::nas().debug(
      "Encoded AuthenticationParameterAutn len (%d)", encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int AuthenticationParameterAutn::Decode(
    const uint8_t* const buf, int len, bool is_iei) {
  uint8_t decoded_size = 0;
  uint8_t octet        = 0;
  oai::logger::logger_common::nas().debug("Decoding %s", GetIeName().c_str());

  // IEI and Length
  int decoded_header_size = Type4NasIe::Decode(buf + decoded_size, len, is_iei);
  if (decoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  decoded_size += decoded_header_size;

  if (GetLengthIndicator() != kAuthenticationParameterAutnValueLength)
    return KEncodeDecodeError;

  for (int i = 0; i < kAuthenticationParameterAutnValueLength; i++) {
    DECODE_U8(buf + decoded_size, value_[i], decoded_size);
  }
  for (int j = 0; j < kAuthenticationParameterAutnValueLength; j++) {
    oai::logger::logger_common::nas().debug(
        "Decoded AuthenticationParameterAutn value (0x%2x)", value_[j]);
  }
  oai::logger::logger_common::nas().debug(
      "Decoded %s, len (%d)", GetIeName().c_str(), decoded_size);
  return decoded_size;
}
