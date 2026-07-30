/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionIdentity.hpp"

#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
PduSessionIdentity::PduSessionIdentity(uint8_t value) : NasIe() {
  value_ = value;
}

//------------------------------------------------------------------------------
PduSessionIdentity::PduSessionIdentity() : NasIe() {
  value_ = 0;
}

//------------------------------------------------------------------------------
PduSessionIdentity::~PduSessionIdentity() {}

//------------------------------------------------------------------------------
uint32_t PduSessionIdentity::GetIeLength() const {
  return kPduSessionIdentityLength;
}

//------------------------------------------------------------------------------
void PduSessionIdentity::Set(uint8_t value) {
  value_ = value;
}

//------------------------------------------------------------------------------
uint8_t PduSessionIdentity::Get() const {
  return value_;
}

//------------------------------------------------------------------------------
bool PduSessionIdentity::Validate(int len) const {
  if (len < kPduSessionIdentityLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kPduSessionIdentityLength);
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
int PduSessionIdentity::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());

  if (len < kPduSessionIdentityLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kPduSessionIdentityLength);
    return KEncodeDecodeError;
  }
  int encoded_size = 0;

  // Value
  ENCODE_U8(buf + encoded_size, value_, encoded_size);

  oai::logger::logger_common::nas().debug(
      "Encoded %s, len (%d)", GetIeName().c_str(), encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int PduSessionIdentity::Decode(const uint8_t* const buf, int len, bool is_iei) {
  oai::logger::logger_common::nas().debug("Decoding %s", GetIeName().c_str());

  if (len < kPduSessionIdentityLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kPduSessionIdentityLength);
    return KEncodeDecodeError;
  }

  int decoded_size = 0;
  // Value
  DECODE_U8(buf + decoded_size, value_, decoded_size);

  oai::logger::logger_common::nas().debug("Decoded value 0x%x", value_);
  oai::logger::logger_common::nas().debug(
      "Decoded %s, len (%d)", GetIeName().c_str(), decoded_size);
  return decoded_size;
}
