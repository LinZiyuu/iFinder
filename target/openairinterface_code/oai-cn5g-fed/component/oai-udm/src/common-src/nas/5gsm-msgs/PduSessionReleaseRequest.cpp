/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionReleaseRequest.hpp"

#include "NasHelper.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
PduSessionReleaseRequest::PduSessionReleaseRequest()
    : Nas5gsmMessage(k5gsSessionManagementMessages, kPduSessionReleaseRequest) {
  ie_5gsm_cause_                              = std::nullopt;
  ie_extended_protocol_configuration_options_ = std::nullopt;
}

//------------------------------------------------------------------------------
PduSessionReleaseRequest::~PduSessionReleaseRequest() {}

//------------------------------------------------------------------------------
uint32_t PduSessionReleaseRequest::GetLength() const {
  uint32_t msg_len = 0;
  msg_len += Nas5gsmMessage::GetLength();

  if (ie_5gsm_cause_.has_value())
    msg_len += ie_5gsm_cause_.value().GetIeLength();

  if (ie_extended_protocol_configuration_options_.has_value())
    msg_len +=
        ie_extended_protocol_configuration_options_.value().GetIeLength();

  return msg_len;
}

//------------------------------------------------------------------------------
void PduSessionReleaseRequest::Set5gsmCause(const _5gsmCause& _5gsm_cause) {
  ie_5gsm_cause_ = std::make_optional<_5gsmCause>(_5gsm_cause);
  ie_5gsm_cause_.value().SetIei(kIei5gsmCause);
}

//------------------------------------------------------------------------------
void PduSessionReleaseRequest::Get5gsmCause(
    std::optional<_5gsmCause>& _5gsm_cause) const {
  _5gsm_cause = ie_5gsm_cause_;
}

//------------------------------------------------------------------------------
void PduSessionReleaseRequest::SetExtendedProtocolConfigurationOptions(
    const ExtendedProtocolConfigurationOptions& options) {
  ie_extended_protocol_configuration_options_ =
      std::make_optional<ExtendedProtocolConfigurationOptions>(options);
}

//------------------------------------------------------------------------------
void PduSessionReleaseRequest::GetExtendedProtocolConfigurationOptions(
    std::optional<ExtendedProtocolConfigurationOptions>& options) const {
  options = ie_extended_protocol_configuration_options_;
}

//------------------------------------------------------------------------------
int PduSessionReleaseRequest::Encode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Encoding PduSessionReleaseRequest message");
  int encoded_size    = 0;
  int encoded_ie_size = 0;
  // Header
  if ((encoded_ie_size = Nas5gsmMessage::Encode(buf, len)) ==
      KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Encoding NAS Header error");
    return KEncodeDecodeError;
  }
  encoded_size += encoded_ie_size;

  // 5GSM cause
  if ((encoded_ie_size = NasHelper::Encode(
           ie_5gsm_cause_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // Extended protocol configuration options
  if ((encoded_ie_size = NasHelper::Encode(
           ie_extended_protocol_configuration_options_, buf, len,
           encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  oai::logger::logger_common::nas().debug(
      "Encoded PduSessionReleaseRequest message len (%d)", encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int PduSessionReleaseRequest::Decode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Decoding PduSessionReleaseRequest message");
  int decoded_size    = 0;
  int decoded_ie_size = 0;

  // Header
  decoded_ie_size = Nas5gsmMessage::Decode(buf, len);
  if (decoded_ie_size == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Decoding NAS Header error");
    return KEncodeDecodeError;
  }
  decoded_size += decoded_ie_size;

  // Decode other IEs
  uint8_t octet = 0x00;
  DECODE_U8_VALUE(buf, octet, decoded_size, len);
  oai::logger::logger_common::nas().debug("First option IEI (0x%x)", octet);
  bool flag = false;
  while ((octet != 0x0)) {
    switch (octet) {
      case kIei5gsmCause: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIei5gsmCause);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_5gsm_cause_, buf, len, decoded_size, true)) ==
            KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

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
      "Decoded PduSessionReleaseRequest message len (%d)", decoded_size);
  return decoded_size;
}
