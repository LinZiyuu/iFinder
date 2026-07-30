/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionStatus.hpp"

#include "3gpp_24.501.hpp"
#include "IeConst.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
PduSessionStatus::PduSessionStatus() : Type4NasIe(kIeiPduSessionStatus) {
  value_ = 0;
  SetLengthIndicator(kPduSessionStatusContentMinimumLength);
}

//------------------------------------------------------------------------------
PduSessionStatus::PduSessionStatus(uint16_t value)
    : Type4NasIe(kIeiPduSessionStatus) {
  value_ = value;
  SetLengthIndicator(kPduSessionStatusContentMinimumLength);
}

//------------------------------------------------------------------------------
// PduSessionStatus::~PduSessionStatus() {}

//------------------------------------------------------------------------------
void PduSessionStatus::SetValue(uint16_t value) {
  value_ = value;
}

//------------------------------------------------------------------------------
uint16_t PduSessionStatus::GetValue() const {
  return value_;
}

//------------------------------------------------------------------------------
int PduSessionStatus::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());

  int encoded_size = 0;
  // Validate the buffer's length and Encode IEI/Length
  int encoded_header_size = Type4NasIe::Encode(buf + encoded_size, len);
  if (encoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  encoded_size += encoded_header_size;

  // Value
  ENCODE_U16(buf + encoded_size, value_, encoded_size);

  oai::logger::logger_common::nas().debug(
      "Encoded %s, len (%d)", GetIeName().c_str(), encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int PduSessionStatus::Decode(const uint8_t* const buf, int len, bool is_iei) {
  oai::logger::logger_common::nas().debug("Decoding %s", GetIeName().c_str());

  int decoded_size = 0;

  // IEI and Length
  int decoded_header_size = Type4NasIe::Decode(buf + decoded_size, len, is_iei);
  if (decoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  decoded_size += decoded_header_size;

  DECODE_U16(buf + decoded_size, value_, decoded_size);

  oai::logger::logger_common::nas().debug(
      "Decoded %s, value 0x%x len %d", GetIeName().c_str(), value_,
      decoded_size);
  return decoded_size;
}
