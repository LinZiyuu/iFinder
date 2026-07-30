/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "EpsBearerContextStatus.hpp"

#include "3gpp_24.501.hpp"
#include "IeConst.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
EpsBearerContextStatus::EpsBearerContextStatus()
    : Type4NasIe(kIeiEpsBearerContextStatus) {
  value_ = 0;
  SetLengthIndicator(kEpsBearerContextStatusContentLength);
}

//------------------------------------------------------------------------------
EpsBearerContextStatus::EpsBearerContextStatus(uint16_t value) {
  value_ = value;
  SetLengthIndicator(kEpsBearerContextStatusContentLength);
}

//------------------------------------------------------------------------------
EpsBearerContextStatus::~EpsBearerContextStatus() {}

//------------------------------------------------------------------------------
void EpsBearerContextStatus::SetValue(uint16_t value) {
  value_ = value;
}

//------------------------------------------------------------------------------
uint16_t EpsBearerContextStatus::GetValue() const {
  return value_;
}

//------------------------------------------------------------------------------
int EpsBearerContextStatus::Encode(uint8_t* buf, int len) const {
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
int EpsBearerContextStatus::Decode(
    const uint8_t* const buf, int len, bool is_iei) {
  if (len < kEpsBearerContextStatusLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kEpsBearerContextStatusLength);
    return KEncodeDecodeError;
  }

  uint8_t decoded_size = 0;
  uint8_t octet        = 0;
  oai::logger::logger_common::nas().debug("Decoding %s", GetIeName().c_str());

  // IEI and Length
  int decoded_header_size = Type4NasIe::Decode(buf + decoded_size, len, is_iei);
  if (decoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  decoded_size += decoded_header_size;

  // Value
  DECODE_U16(buf + decoded_size, value_, decoded_size);  // for IE

  oai::logger::logger_common::nas().debug(
      "EPS_Bearer_Context_Status, value 0x%0x", value_);
  oai::logger::logger_common::nas().debug(
      "Decoded %s, len (%d)", GetIeName().c_str(), decoded_size);
  return decoded_size;
}
