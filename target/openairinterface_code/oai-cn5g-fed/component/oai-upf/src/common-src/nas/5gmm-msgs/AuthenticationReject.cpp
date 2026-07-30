/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "AuthenticationReject.hpp"

#include "NasHelper.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
AuthenticationReject::AuthenticationReject()
    : ie_header_(
          k5gsMobilityManagementMessages, kPlain5gsMessage,
          kAuthenticationReject) {
  ie_eap_message_ = std::nullopt;
}

//------------------------------------------------------------------------------
AuthenticationReject::~AuthenticationReject() {}

//------------------------------------------------------------------------------
uint32_t AuthenticationReject::GetLength() const {
  uint32_t msg_len = 0;
  msg_len += ie_header_.GetLength();
  if (ie_eap_message_.has_value())
    msg_len += ie_eap_message_.value().GetIeLength();

  return msg_len;
}

//------------------------------------------------------------------------------
void AuthenticationReject::SetHeader(uint8_t security_header_type) {
  ie_header_.SetSecurityHeaderType(security_header_type);
}

//------------------------------------------------------------------------------
void AuthenticationReject::SetEapMessage(const bstring& eap) {
  ie_eap_message_ = std::make_optional<EapMessage>(kIeiEapMessage, eap);
}

//------------------------------------------------------------------------------
int AuthenticationReject::Encode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Encoding AuthenticationReject message");

  if (!Validate(len)) return KEncodeDecodeError;

  int encoded_size    = 0;
  int encoded_ie_size = 0;

  // Header
  if ((encoded_ie_size = ie_header_.Encode(buf, len)) == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Encoding NAS Header error");
    return KEncodeDecodeError;
  }
  encoded_size += encoded_ie_size;

  // EAP Message
  if ((encoded_ie_size = NasHelper::Encode(
           ie_eap_message_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  oai::logger::logger_common::nas().debug(
      "Encoded AuthenticationReject message len (%d)", encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int AuthenticationReject::Decode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Decoding AuthenticationReject message");

  int decoded_size    = 0;
  int decoded_ie_size = 0;
  // Header
  decoded_ie_size = ie_header_.Decode(buf, len);
  if (decoded_ie_size == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Decoding NAS Header error");
    return KEncodeDecodeError;
  }
  decoded_size += decoded_ie_size;

  // IEIs
  uint8_t octet = 0x00;
  DECODE_U8_VALUE(buf, octet, decoded_size, len);
  while ((octet != 0x0)) {
    oai::logger::logger_common::nas().debug("Decoding IEI (0x%x)", octet);
    switch (octet) {
      case kIeiEapMessage: {
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_eap_message_, buf, len, decoded_size, true)) ==
            KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

      default: {
        oai::logger::logger_common::nas().warn(
            "Unknown IEI 0x%x, stop decoding...", octet);
        // Stop decoding
        octet = 0x00;
      } break;
    }
  }

  oai::logger::logger_common::nas().debug(
      "Decoded AuthenticationReject message len (%d)", decoded_size);
  return decoded_size;
}
