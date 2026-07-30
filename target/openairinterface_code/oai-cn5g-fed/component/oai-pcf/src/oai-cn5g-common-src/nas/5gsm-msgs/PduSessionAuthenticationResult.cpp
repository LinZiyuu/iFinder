/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionAuthenticationResult.hpp"

#include "NasHelper.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
PduSessionAuthenticationResult::PduSessionAuthenticationResult()
    : Nas5gsmMessage(
          k5gsSessionManagementMessages, kPduSessionAuthenticationResult) {
  ie_extended_protocol_configuration_options_ = std::nullopt;
}

//------------------------------------------------------------------------------
PduSessionAuthenticationResult::~PduSessionAuthenticationResult() {}

//------------------------------------------------------------------------------
uint32_t PduSessionAuthenticationResult::GetLength() const {
  uint32_t msg_len = 0;
  msg_len += Nas5gsmMessage::GetLength();
  msg_len += ie_eap_message_.GetIeLength();

  if (ie_extended_protocol_configuration_options_.has_value())
    msg_len +=
        ie_extended_protocol_configuration_options_.value().GetIeLength();

  return msg_len;
}

//------------------------------------------------------------------------------
void PduSessionAuthenticationResult::SetEapMessage(
    const EapMessage& eap_message) {
  ie_eap_message_ = eap_message;
  ie_eap_message_.SetIei(kIeiEapMessage);
}

//------------------------------------------------------------------------------
void PduSessionAuthenticationResult::GetEapMessage(
    EapMessage& eap_message) const {
  eap_message = ie_eap_message_;
}

//------------------------------------------------------------------------------
void PduSessionAuthenticationResult::SetExtendedProtocolConfigurationOptions(
    const ExtendedProtocolConfigurationOptions& options) {
  ie_extended_protocol_configuration_options_ =
      std::make_optional<ExtendedProtocolConfigurationOptions>(options);
}

//------------------------------------------------------------------------------
void PduSessionAuthenticationResult::GetExtendedProtocolConfigurationOptions(
    std::optional<ExtendedProtocolConfigurationOptions>& options) const {
  options = ie_extended_protocol_configuration_options_;
}

//------------------------------------------------------------------------------
int PduSessionAuthenticationResult::Encode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Encoding PduSessionAuthenticationResult message");
  int encoded_size    = 0;
  int encoded_ie_size = 0;
  // Header
  if ((encoded_ie_size = Nas5gsmMessage::Encode(buf, len)) ==
      KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Encoding NAS Header error");
    return KEncodeDecodeError;
  }
  encoded_size += encoded_ie_size;

  // EAP message
  if ((encoded_ie_size = NasHelper::Encode(
           ie_eap_message_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // Extended protocol configuration options
  if ((encoded_ie_size = NasHelper::Encode(
           ie_extended_protocol_configuration_options_, buf, len,
           encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  oai::logger::logger_common::nas().debug(
      "Encoded PduSessionAuthenticationResult message len (%d)", encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int PduSessionAuthenticationResult::Decode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Decoding PduSessionAuthenticationResult message");
  int decoded_size    = 0;
  int decoded_ie_size = 0;

  // Header
  decoded_ie_size = Nas5gsmMessage::Decode(buf, len);
  if (decoded_ie_size == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Decoding NAS Header error");
    return KEncodeDecodeError;
  }
  decoded_size += decoded_ie_size;

  // EAP message
  if ((decoded_ie_size =
           NasHelper::Decode(ie_eap_message_, buf, len, decoded_size, true)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // Decode other IEs
  uint8_t octet = 0x00;
  DECODE_U8_VALUE(buf, octet, decoded_size, len);
  oai::logger::logger_common::nas().debug("First option IEI (0x%x)", octet);
  bool flag = false;
  while ((octet != 0x0)) {
    switch (octet) {
      case kIeiExtendedProtocolConfigurationOptions: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiExtendedProtocolConfigurationOptions);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_extended_protocol_configuration_options_, buf, len,
                 decoded_size, true)) == KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

      default: {
        // TODO:
        if (flag) {
          oai::logger::logger_common::nas().warn(
              "Unknown IEI 0x%x, stop decoding...", octet);
          // Stop decoding
          octet = 0x00;
        }
      } break;
    }
  }

  oai::logger::logger_common::nas().debug(
      "Decoded PduSessionAuthenticationResult message len (%d)", decoded_size);
  return decoded_size;
}
