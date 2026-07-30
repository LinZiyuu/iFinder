/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "_5gsmCongestionReAttemptIndicator.hpp"

#include "3gpp_24.501.hpp"
#include "IeConst.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
_5gsmCongestionReAttemptIndicator::_5gsmCongestionReAttemptIndicator()
    : Type4NasIe(kIei5gsmCongestionReAttemptIndicator), abo_(false) {
  SetLengthIndicator(k5gsmCongestionReAttemptIndicatorContentLength);
}

//------------------------------------------------------------------------------
_5gsmCongestionReAttemptIndicator::_5gsmCongestionReAttemptIndicator(bool abo)
    : Type4NasIe(kIei5gsmCongestionReAttemptIndicator), abo_(abo) {
  SetLengthIndicator(k5gsmCongestionReAttemptIndicatorContentLength);
}

//------------------------------------------------------------------------------
_5gsmCongestionReAttemptIndicator::~_5gsmCongestionReAttemptIndicator() {}

//------------------------------------------------------------------------------
void _5gsmCongestionReAttemptIndicator::SetAbo(bool abo) {
  abo_ = abo;
  SetLengthIndicator(k5gsmCongestionReAttemptIndicatorContentLength);
}

//------------------------------------------------------------------------------
bool _5gsmCongestionReAttemptIndicator::GetAbo() const {
  return abo_;
}

//------------------------------------------------------------------------------
int _5gsmCongestionReAttemptIndicator::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());
  int ie_len = GetIeLength();

  int encoded_size = 0;
  // Validate the buffer's length and Encode IEI/Length
  int encoded_header_size = Type4NasIe::Encode(buf + encoded_size, len);
  if (encoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  encoded_size += encoded_header_size;

  // Octet 3
  uint8_t octet3 = {};
  octet3         = abo_ ? 1 : 0;
  ENCODE_U8(buf + encoded_size, octet3, encoded_size);

  oai::logger::logger_common::nas().debug(
      "Encoded %s, len (%d)", GetIeName().c_str(), encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int _5gsmCongestionReAttemptIndicator::Decode(
    const uint8_t* const buf, int len, bool is_iei) {
  if (len < k5gsmCongestionReAttemptIndicatorLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        k5gsmCongestionReAttemptIndicatorLength);
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
  abo_ = octet3 & 0x01;

  oai::logger::logger_common::nas().debug(
      "Decoded %s, len (%d)", GetIeName().c_str(), decoded_size);
  return decoded_size;
}
