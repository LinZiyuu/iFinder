/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "DeregistrationAccept.hpp"

#include "NasHelper.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
DeregistrationAccept::DeregistrationAccept(bool is_ue_originating)
    : ie_header_() {
  ie_header_.SetEpd(k5gsMobilityManagementMessages);
  if (is_ue_originating) {
    ie_header_.SetMessageType(kDeregistrationAcceptUeOriginating);
  } else {
    ie_header_.SetMessageType(kDeregistrationAcceptUeTerminated);
  }
}

//------------------------------------------------------------------------------
DeregistrationAccept::~DeregistrationAccept() {}

//------------------------------------------------------------------------------
uint32_t DeregistrationAccept::GetLength() const {
  uint32_t msg_len = 0;
  msg_len += ie_header_.GetLength();

  return msg_len;
}

//------------------------------------------------------------------------------
void DeregistrationAccept::SetHeader(uint8_t security_header_type) {
  ie_header_.SetSecurityHeaderType(security_header_type);
}

//------------------------------------------------------------------------------
int DeregistrationAccept::Encode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Encoding De-registration Accept message");

  int encoded_size    = 0;
  int encoded_ie_size = 0;

  // Header
  if ((encoded_ie_size = ie_header_.Encode(buf, len)) == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Encoding NAS Header error");
    return KEncodeDecodeError;
  }
  encoded_size += encoded_ie_size;

  oai::logger::logger_common::nas().debug(
      "Encoded De-registration Accept message len (%d)", encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int DeregistrationAccept::Decode(uint8_t* buf, int len) {
  int decoded_size   = 0;
  int decoded_result = 0;

  // Header
  decoded_result = ie_header_.Decode(buf, len);
  if (decoded_result == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Decoding NAS Header error");
    return KEncodeDecodeError;
  }
  decoded_size += decoded_result;

  oai::logger::logger_common::nas().debug(
      "Decoded De-registrationReject message len (%d)", decoded_size);
  return decoded_size;
}
