/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "AuthenticationParameterRand.hpp"

#include "3gpp_24.501.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"
using namespace oai::nas;

//------------------------------------------------------------------------------
AuthenticationParameterRand::AuthenticationParameterRand()
    : Type3NasIe(), value_() {}

//------------------------------------------------------------------------------
AuthenticationParameterRand::AuthenticationParameterRand(uint8_t iei)
    : Type3NasIe(iei), value_() {}

//------------------------------------------------------------------------------
AuthenticationParameterRand::AuthenticationParameterRand(
    uint8_t iei, uint8_t value[kAuthenticationParameterRandValueLength])
    : Type3NasIe(iei) {
  for (int i = 0; i < kAuthenticationParameterRandValueLength; i++) {
    this->value_[i] = value[i];
  }
}

//------------------------------------------------------------------------------
AuthenticationParameterRand::~AuthenticationParameterRand() {}

//------------------------------------------------------------------------------
uint32_t AuthenticationParameterRand::GetIeLength() const {
  return (kAuthenticationParameterRandLength - 1 + Type3NasIe::GetIeLength());
}

//------------------------------------------------------------------------------
int AuthenticationParameterRand::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());

  if (len < kAuthenticationParameterRandLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kAuthenticationParameterRandLength);
    return KEncodeDecodeError;
  }
  int encoded_size = 0;

  // IEI
  encoded_size += Type3NasIe::Encode(buf + encoded_size, len);

  for (int i = 0; i < kAuthenticationParameterRandValueLength; i++) {
    ENCODE_U8(buf + encoded_size, value_[i], encoded_size);
  }

  oai::logger::logger_common::nas().debug(
      "Encoded %s, len (%d)", GetIeName().c_str(), encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int AuthenticationParameterRand::Decode(
    const uint8_t* const buf, int len, bool is_iei) {
  oai::logger::logger_common::nas().debug("Decoding %s", GetIeName().c_str());

  if (len < kAuthenticationParameterRandLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kAuthenticationParameterRandLength);
    return KEncodeDecodeError;
  }

  int decoded_size = 0;

  // IEI and Length
  decoded_size += Type3NasIe::Decode(buf + decoded_size, len, is_iei);

  for (int i = 0; i < kAuthenticationParameterRandValueLength; i++) {
    DECODE_U8(buf + decoded_size, value_[i], decoded_size);
  }

  for (int j = 0; j < kAuthenticationParameterRandValueLength; j++) {
    oai::logger::logger_common::nas().debug(
        "Decoded AuthenticationParameterRand value (0x%2x)", value_[j]);
  }

  oai::logger::logger_common::nas().debug(
      "Decoded %s, len (%d)", GetIeName().c_str(), decoded_size);
  return decoded_size;
}
