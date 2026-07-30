/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "AuthenticationResult.hpp"

#include "NasHelper.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
AuthenticationResult::AuthenticationResult()
    : ie_header_(
          k5gsMobilityManagementMessages, kPlain5gsMessage,
          kAuthenticationResult) {
  ie_abba_ = std::nullopt;
}

//------------------------------------------------------------------------------
AuthenticationResult::~AuthenticationResult() {}

//------------------------------------------------------------------------------
uint32_t AuthenticationResult::GetLength() const {
  uint32_t msg_len = 0;
  msg_len += ie_header_.GetLength();
  // msg_len += ie_ng_ksi_.GetIeLength();
  msg_len += 1;  // 1/2 for ngKSI + 1/2 for Spare half octet
  msg_len += ie_eap_message_.GetIeLength();
  if (ie_abba_.has_value()) msg_len += ie_abba_.value().GetIeLength();

  return msg_len;
}

//------------------------------------------------------------------------------
void AuthenticationResult::SetHeader(uint8_t security_header_type) {
  ie_header_.SetSecurityHeaderType(security_header_type);
}

//------------------------------------------------------------------------------
void AuthenticationResult::SetNgKsi(uint8_t tsc, uint8_t key_set_id) {
  ie_ng_ksi_.Set(false);  // 4 lower bits
  ie_ng_ksi_.SetTypeOfSecurityContext(tsc);
  ie_ng_ksi_.SetNasKeyIdentifier(key_set_id);
}

//------------------------------------------------------------------------------
void AuthenticationResult::SetAbba(uint8_t length, uint8_t* value) {
  ie_abba_ = std::make_optional<Abba>(kIeiAbba, length, value);
}

//------------------------------------------------------------------------------
void AuthenticationResult::SetEapMessage(const bstring& eap) {
  ie_eap_message_.SetValue(eap);
}

//------------------------------------------------------------------------------
int AuthenticationResult::Encode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Encoding AuthenticationResult message");

  if (!Validate(len)) return KEncodeDecodeError;

  int encoded_size    = 0;
  int encoded_ie_size = 0;

  // Header
  if ((encoded_ie_size = ie_header_.Encode(buf, len)) == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Encoding NAS Header error");
    return KEncodeDecodeError;
  }
  encoded_size += encoded_ie_size;

  // ngKSI
  if ((encoded_ie_size = NasHelper::Encode(
           ie_ng_ksi_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }
  // Spare half octet
  if (encoded_ie_size == 0)
    encoded_size++;  // 1/2 octet + 1/2 octet from ie_ng_ksi

  // EAP message
  if ((encoded_ie_size = NasHelper::Encode(
           ie_eap_message_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // ABBA
  if ((encoded_ie_size = NasHelper::Encode(ie_abba_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  oai::logger::logger_common::nas().debug(
      "Encoded AuthenticationResult message len (%d)", encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int AuthenticationResult::Decode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Decoding AuthenticationResult message");
  int decoded_size    = 0;
  int decoded_ie_size = 0;
  // Header
  decoded_ie_size = ie_header_.Decode(buf, len);
  if (decoded_ie_size == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Decoding NAS Header error");
    return KEncodeDecodeError;
  }
  decoded_size += decoded_ie_size;

  // NAS key set identifier
  if ((decoded_ie_size = NasHelper::Decode(
           ie_ng_ksi_, buf, len, decoded_size, false, false)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }
  if (decoded_ie_size == 0)
    decoded_size++;  // 1/2 octet for ngKSI, 1/2 for Spare half octet

  // EAP message
  if ((decoded_ie_size =
           NasHelper::Decode(ie_eap_message_, buf, len, decoded_size, false)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  oai::logger::logger_common::nas().debug("Decoded_size (%d)", decoded_size);

  // Decode other IEs
  uint8_t octet = 0x00;
  DECODE_U8_VALUE(buf, octet, decoded_size, len);
  oai::logger::logger_common::nas().debug("First option IEI (0x%x)", octet);
  while ((octet != 0x0)) {
    oai::logger::logger_common::nas().debug("Decoding IEI 0x%x", octet);
    switch (octet) {
      case kIeiAbba: {
        if ((decoded_ie_size =
                 NasHelper::Decode(ie_abba_, buf, len, decoded_size, true)) ==
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
      "Decoded AuthenticationResult message len (%d)", decoded_size);
  return decoded_size;
}
