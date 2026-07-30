/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "_5gmmStatus.hpp"

#include "NasHelper.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
_5gmmStatus::_5gmmStatus()
    : ie_header_(
          k5gsMobilityManagementMessages, kPlain5gsMessage, k5gmmStatus) {}

//------------------------------------------------------------------------------
_5gmmStatus::~_5gmmStatus() {}

//------------------------------------------------------------------------------
uint32_t _5gmmStatus::GetLength() const {
  uint32_t msg_len = 0;
  msg_len += ie_header_.GetLength();
  msg_len += ie_5gmm_cause_.GetIeLength();

  return msg_len;
}

//------------------------------------------------------------------------------
void _5gmmStatus::SetHeader(uint8_t security_header_type) {
  ie_header_.SetSecurityHeaderType(security_header_type);
}

//------------------------------------------------------------------------------
void _5gmmStatus::Set5gmmCause(uint8_t value) {
  ie_5gmm_cause_.SetValue(value);
}

//------------------------------------------------------------------------------
uint8_t _5gmmStatus::Get5gmmCause() const {
  return ie_5gmm_cause_.GetValue();
}

//------------------------------------------------------------------------------
int _5gmmStatus::Encode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug("Encoding _5gmmStatus message");

  if (!Validate(len)) return KEncodeDecodeError;

  int encoded_size    = 0;
  int encoded_ie_size = 0;

  // Header
  if ((encoded_ie_size = ie_header_.Encode(buf, len)) == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Encoding NAS Header error");
    return KEncodeDecodeError;
  }
  encoded_size += encoded_ie_size;

  // 5GMM Cause
  if ((encoded_ie_size = NasHelper::Encode(
           ie_5gmm_cause_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  oai::logger::logger_common::nas().debug(
      "Encoded _5gmmStatus message len (%d)", encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int _5gmmStatus::Decode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug("Decoding _5gmmStatus message");

  int decoded_size    = 0;
  int decoded_ie_size = 0;

  // Header
  decoded_ie_size = ie_header_.Decode(buf, len);
  if (decoded_ie_size == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Decoding NAS Header error");
    return KEncodeDecodeError;
  }
  decoded_size += decoded_ie_size;

  // 5GMM Cause
  if ((decoded_ie_size =
           NasHelper::Decode(ie_5gmm_cause_, buf, len, decoded_size, false)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  oai::logger::logger_common::nas().debug(
      "Decoded _5gmmStatus message len (%d)", decoded_size);
  return decoded_size;
}
