/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "ProcedureTransactionIdentity.hpp"

#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
ProcedureTransactionIdentity::ProcedureTransactionIdentity(uint8_t value)
    : NasIe() {
  value_ = value;
}

//------------------------------------------------------------------------------
ProcedureTransactionIdentity::ProcedureTransactionIdentity() : NasIe() {
  value_ = 0;
}

//------------------------------------------------------------------------------
ProcedureTransactionIdentity::~ProcedureTransactionIdentity() {}

//------------------------------------------------------------------------------
uint32_t ProcedureTransactionIdentity::GetIeLength() const {
  return kProcedureTransactionIdentityLength;
}

//------------------------------------------------------------------------------
void ProcedureTransactionIdentity::Set(uint8_t value) {
  value_ = value;
}

//------------------------------------------------------------------------------
uint8_t ProcedureTransactionIdentity::Get() const {
  return value_;
}

//------------------------------------------------------------------------------
bool ProcedureTransactionIdentity::Validate(int len) const {
  if (len < kProcedureTransactionIdentityLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kProcedureTransactionIdentityLength);
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
int ProcedureTransactionIdentity::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());

  if (len < kProcedureTransactionIdentityLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kProcedureTransactionIdentityLength);
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
int ProcedureTransactionIdentity::Decode(
    const uint8_t* const buf, int len, bool is_iei) {
  oai::logger::logger_common::nas().debug("Decoding %s", GetIeName().c_str());

  if (len < kProcedureTransactionIdentityLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kProcedureTransactionIdentityLength);
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
