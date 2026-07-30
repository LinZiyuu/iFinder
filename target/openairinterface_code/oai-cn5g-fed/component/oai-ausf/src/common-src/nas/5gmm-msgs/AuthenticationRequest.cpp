/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "AuthenticationRequest.hpp"

#include "NasHelper.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
AuthenticationRequest::AuthenticationRequest()
    : ie_header_(
          k5gsMobilityManagementMessages, kPlain5gsMessage,
          kAuthenticationRequest) {
  ie_authentication_parameter_rand_ = std::nullopt;
  ie_authentication_parameter_autn_ = std::nullopt;
  ie_eap_message_                   = std::nullopt;
}

//------------------------------------------------------------------------------
AuthenticationRequest::~AuthenticationRequest() {}

//------------------------------------------------------------------------------
uint32_t AuthenticationRequest::GetLength() const {
  uint32_t msg_len = 0;
  msg_len += ie_header_.GetLength();
  // msg_len += ie_ng_ksi_.GetIeLength();
  msg_len += 1;  // 1/2 for ngKSI + 1/2 for Spare half octet
  msg_len += ie_abba_.GetIeLength();
  if (ie_authentication_parameter_rand_.has_value())
    msg_len += ie_authentication_parameter_rand_.value().GetIeLength();
  if (ie_authentication_parameter_autn_.has_value())
    msg_len += ie_authentication_parameter_autn_.value().GetIeLength();
  if (ie_eap_message_.has_value())
    msg_len += ie_eap_message_.value().GetIeLength();

  return msg_len;
}

//------------------------------------------------------------------------------
void AuthenticationRequest::SetHeader(uint8_t security_header_type) {
  ie_header_.SetSecurityHeaderType(security_header_type);
}

//------------------------------------------------------------------------------
void AuthenticationRequest::SetNgKsi(uint8_t tsc, uint8_t key_set_id) {
  ie_ng_ksi_.Set(false);  // 4 lower bits
  ie_ng_ksi_.SetNasKeyIdentifier(key_set_id);
  ie_ng_ksi_.SetTypeOfSecurityContext(tsc);
}

//------------------------------------------------------------------------------
void AuthenticationRequest::SetAbba(uint8_t length, uint8_t* value) {
  ie_abba_.Set(length, value);
}

//------------------------------------------------------------------------------
void AuthenticationRequest::SetAuthenticationParameterRand(
    uint8_t value[kAuthenticationParameterRandValueLength]) {
  ie_authentication_parameter_rand_ =
      std::make_optional<AuthenticationParameterRand>(
          kIeiAuthenticationParameterRand, value);
}

//------------------------------------------------------------------------------
void AuthenticationRequest::SetAuthenticationParameterAutn(
    uint8_t value[kAuthenticationParameterAutnValueLength]) {
  ie_authentication_parameter_autn_ =
      std::make_optional<AuthenticationParameterAutn>(
          kIeiAuthenticationParameterAutn, value);
}

//------------------------------------------------------------------------------
void AuthenticationRequest::SetEapMessage(const bstring& eap) {
  ie_eap_message_ = std::make_optional<EapMessage>(kIeiEapMessage, eap);
}

//------------------------------------------------------------------------------
int AuthenticationRequest::Encode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Encoding AuthenticationRequest message");

  if (!Validate(len)) return KEncodeDecodeError;

  int encoded_size    = 0;
  int encoded_ie_size = 0;

  // Header
  if ((encoded_ie_size = ie_header_.Encode(buf, len)) == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Encoding NAS Header error");
    return KEncodeDecodeError;
  }
  encoded_size += encoded_ie_size;

  if ((encoded_ie_size = NasHelper::Encode(
           ie_ng_ksi_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }
  // Spare half octet
  if (encoded_ie_size == 0)
    encoded_size++;  // 1/2 octet + 1/2 octet from ie_ng_ksi_

  // ABBA
  if ((encoded_ie_size = NasHelper::Encode(ie_abba_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // Authentication parameter RAND
  if ((encoded_ie_size = NasHelper::Encode(
           ie_authentication_parameter_rand_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // Authentication parameter AUTN
  if ((encoded_ie_size = NasHelper::Encode(
           ie_authentication_parameter_autn_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // EAP message
  if ((encoded_ie_size = NasHelper::Encode(
           ie_eap_message_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  oai::logger::logger_common::nas().debug(
      "Encoded AuthenticationRequest message (len %d)", encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int AuthenticationRequest::Decode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Decoding RegistrationReject message");
  int decoded_size    = 0;
  int decoded_ie_size = 0;

  // Header
  decoded_ie_size = ie_header_.Decode(buf, len);
  if (decoded_ie_size == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Decoding NAS Header error");
    return KEncodeDecodeError;
  }
  decoded_size += decoded_ie_size;

  // NgKSI
  if ((decoded_ie_size = NasHelper::Decode(
           ie_ng_ksi_, buf, len, decoded_size, false, false)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }
  if (decoded_ie_size == 0)
    decoded_size++;  // 1/2 octet from ie_ng_ksi, 1/2 from Spare half octet

  // ABBA
  if ((decoded_ie_size = NasHelper::Decode(
           ie_abba_, buf, len, decoded_size, false)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }
  oai::logger::logger_common::nas().debug("Decoded_size %d", decoded_size);

  // Decode other IEs
  uint8_t octet = 0x00;
  DECODE_U8_VALUE(buf, octet, decoded_size, len);
  oai::logger::logger_common::nas().debug("First option IEI 0x%x", octet);
  while ((octet != 0x0)) {
    oai::logger::logger_common::nas().debug("Decoding IEI 0x%x", octet);
    switch (octet) {
      case kIeiAuthenticationParameterRand: {
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_authentication_parameter_rand_, buf, len, decoded_size,
                 true)) == KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI 0x%x", octet);
      } break;

      case kIeiAuthenticationParameterAutn: {
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_authentication_parameter_autn_, buf, len, decoded_size,
                 true)) == KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI 0x%x", octet);
      } break;

      case kIeiEapMessage: {
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_eap_message_, buf, len, decoded_size, true)) ==
            KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI 0x%x", octet);
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
      "Decoded AuthenticationRequest message (len %d)", decoded_size);
  return decoded_size;
}
