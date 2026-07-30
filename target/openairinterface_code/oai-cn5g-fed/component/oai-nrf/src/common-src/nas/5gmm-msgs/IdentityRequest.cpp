/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "IdentityRequest.hpp"

#include "NasHelper.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
IdentityRequest::IdentityRequest()
    : ie_header_(
          k5gsMobilityManagementMessages, kPlain5gsMessage, kIdentityRequest) {}

//------------------------------------------------------------------------------
IdentityRequest::~IdentityRequest() {}

//------------------------------------------------------------------------------
uint32_t IdentityRequest::GetLength() const {
  uint32_t msg_len = 0;
  msg_len += ie_header_.GetLength();
  // msg_len += ie_5gs_identity_type_.GetIeLength();
  msg_len += 1;  // Identity type 1/2 + Spare half octet 1/2

  return msg_len;
}

//------------------------------------------------------------------------------
void IdentityRequest::SetHeader(uint8_t security_header_type) {
  ie_header_.SetSecurityHeaderType(security_header_type);
}

//------------------------------------------------------------------------------
void IdentityRequest::Set5gsIdentityType(uint8_t value) {
  ie_5gs_identity_type_.SetValue(value);
}

//------------------------------------------------------------------------------
int IdentityRequest::Encode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug("Encoding IdentityRequest message");
  int encoded_size    = 0;
  int encoded_ie_size = 0;

  // Header
  if ((encoded_ie_size = ie_header_.Encode(buf, len)) == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Encoding NAS Header error");
    return KEncodeDecodeError;
  }
  encoded_size += encoded_ie_size;

  if ((encoded_ie_size =
           NasHelper::Encode(ie_5gs_identity_type_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  if (encoded_ie_size == 0)
    encoded_size++;  // 1/2 for 5GS Identity Type and 1/2 for spare mode

  oai::logger::logger_common::nas().debug(
      "Encoded IdentityRequest message len (%d)", encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int IdentityRequest::Decode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug("Decoding IdentityRequest message");

  int decoded_size    = 0;
  int decoded_ie_size = 0;

  // Header
  decoded_ie_size = ie_header_.Decode(buf, len);
  if (decoded_ie_size == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Decoding NAS Header error");
    return KEncodeDecodeError;
  }
  decoded_size += decoded_ie_size;

  if ((decoded_ie_size = NasHelper::Decode(
           ie_5gs_identity_type_, buf, len, decoded_size, false)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }
  if (decoded_ie_size == 0) {
    decoded_size++;  // including 1/2 octet for Spare
  }

  oai::logger::logger_common::nas().debug(
      "Decoded IdentityRequest message len (%d)", decoded_size);
  return decoded_size;
}
