/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "ReAttemptIndicator.hpp"

#include "3gpp_24.501.hpp"
#include "IeConst.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
ReAttemptIndicator::ReAttemptIndicator()
    : Type4NasIe(kIeiReAttemptIndicator), eplmnc_(false), ratc_(false) {
  SetLengthIndicator(kReAttemptIndicatorContentLength);
}

//------------------------------------------------------------------------------
ReAttemptIndicator::ReAttemptIndicator(bool eplmnc, bool ratc)
    : Type4NasIe(kIeiReAttemptIndicator), eplmnc_(eplmnc), ratc_(ratc) {
  SetLengthIndicator(kReAttemptIndicatorContentLength);
}

//------------------------------------------------------------------------------
ReAttemptIndicator::~ReAttemptIndicator() {}

//------------------------------------------------------------------------------
void ReAttemptIndicator::SetEplmnc(bool eplmnc) {
  eplmnc_ = eplmnc;
}

//------------------------------------------------------------------------------
bool ReAttemptIndicator::GetEplmnc() const {
  return eplmnc_;
}

//------------------------------------------------------------------------------
void ReAttemptIndicator::SetRatc(bool ratc) {
  ratc_ = ratc;
}

//------------------------------------------------------------------------------
bool ReAttemptIndicator::GetRatc() const {
  return ratc_;
}

//------------------------------------------------------------------------------
int ReAttemptIndicator::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());
  int ie_len = GetIeLength();

  int encoded_size = 0;
  // Validate the buffer's length and Encode IEI/Length
  int encoded_header_size = Type4NasIe::Encode(buf + encoded_size, len);
  if (encoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  encoded_size += encoded_header_size;

  // Octet 3
  uint8_t octet3 = {};
  octet3         = ratc_ ? 1 : 0;
  octet3         = eplmnc_ ? (octet3 | 0x02) : octet3;
  ENCODE_U8(buf + encoded_size, octet3, encoded_size);

  oai::logger::logger_common::nas().debug(
      "Encoded %s, len (%d)", GetIeName().c_str(), encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int ReAttemptIndicator::Decode(const uint8_t* const buf, int len, bool is_iei) {
  if (len < kReAttemptIndicatorLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kReAttemptIndicatorLength);
    return KEncodeDecodeError;
  }

  uint8_t decoded_size = 0;
  oai::logger::logger_common::nas().debug("Decoding %s", GetIeName().c_str());

  // IEI and Length
  int decoded_header_size = Type4NasIe::Decode(buf + decoded_size, len, is_iei);
  if (decoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  decoded_size += decoded_header_size;

  uint8_t octet3 = 0;
  DECODE_U8(buf + decoded_size, octet3, decoded_size);
  ratc_   = octet3 & 0x01;
  eplmnc_ = (octet3 & 0x02) >> 1;

  oai::logger::logger_common::nas().debug(
      "Decoded %s, len (%d)", GetIeName().c_str(), decoded_size);
  return decoded_size;
}
