/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionModificationRequest.hpp"

#include "NasHelper.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
PduSessionModificationRequest::PduSessionModificationRequest()
    : Nas5gsmMessage(
          k5gsSessionManagementMessages, kPduSessionModificationRequest) {
  ie_5gsm_capability_                            = std::nullopt;
  ie_5gsm_cause_                                 = std::nullopt;
  ie_maximum_number_of_supported_packet_filters_ = std::nullopt;
  ie_always_on_pdu_session_requested_            = std::nullopt;
  ie_integrity_protection_maximum_data_rate_     = std::nullopt;
  ie_requested_qos_rules_                        = std::nullopt;
  ie_requested_qos_flow_descriptions_            = std::nullopt;
  ie_extended_protocol_configuration_options_    = std::nullopt;
}

//------------------------------------------------------------------------------
PduSessionModificationRequest::~PduSessionModificationRequest() {}

//------------------------------------------------------------------------------
uint32_t PduSessionModificationRequest::GetLength() const {
  uint32_t msg_len = 0;
  msg_len += Nas5gsmMessage::GetLength();

  if (ie_5gsm_capability_.has_value())
    msg_len += ie_5gsm_capability_.value().GetIeLength();

  if (ie_5gsm_cause_.has_value())
    msg_len += ie_5gsm_cause_.value().GetIeLength();

  if (ie_maximum_number_of_supported_packet_filters_.has_value())
    msg_len +=
        ie_maximum_number_of_supported_packet_filters_.value().GetIeLength();

  if (ie_always_on_pdu_session_requested_.has_value())
    msg_len += ie_always_on_pdu_session_requested_.value().GetIeLength();

  if (ie_integrity_protection_maximum_data_rate_.has_value())
    msg_len += ie_integrity_protection_maximum_data_rate_.value().GetIeLength();

  if (ie_requested_qos_rules_.has_value())
    msg_len += ie_requested_qos_rules_.value().GetIeLength();

  if (ie_requested_qos_flow_descriptions_.has_value())
    msg_len += ie_requested_qos_flow_descriptions_.value().GetIeLength();

  if (ie_extended_protocol_configuration_options_.has_value())
    msg_len +=
        ie_extended_protocol_configuration_options_.value().GetIeLength();

  return msg_len;
}

//------------------------------------------------------------------------------
void PduSessionModificationRequest::Set5gsmCapability(
    const _5gsmCapability& _5gsm_capability) {
  ie_5gsm_capability_ = std::make_optional<_5gsmCapability>(_5gsm_capability);
}

//------------------------------------------------------------------------------
void PduSessionModificationRequest::Get5gsmCapability(
    std::optional<_5gsmCapability>& _5gsm_capability) const {
  _5gsm_capability = ie_5gsm_capability_;
}

//------------------------------------------------------------------------------
void PduSessionModificationRequest::Set5gsmCause(
    const _5gsmCause& _5gsm_cause) {
  ie_5gsm_cause_ = std::make_optional<_5gsmCause>(_5gsm_cause);
  ie_5gsm_cause_.value().SetIei(kIei5gsmCause);
}

//------------------------------------------------------------------------------
void PduSessionModificationRequest::Get5gsmCause(
    std::optional<_5gsmCause>& _5gsm_cause) const {
  _5gsm_cause = ie_5gsm_cause_;
}

//------------------------------------------------------------------------------
void PduSessionModificationRequest::SetMaximumNumberOfSupportedPacketFilters(
    const MaximumNumberOfSupportedPacketFilters& filters) {
  ie_maximum_number_of_supported_packet_filters_ =
      std::make_optional<MaximumNumberOfSupportedPacketFilters>(filters);
}

//------------------------------------------------------------------------------
void PduSessionModificationRequest::GetMaximumNumberOfSupportedPacketFilters(
    std::optional<MaximumNumberOfSupportedPacketFilters>& filters) const {
  filters = ie_maximum_number_of_supported_packet_filters_;
}

//------------------------------------------------------------------------------
void PduSessionModificationRequest::SetAlwaysOnPduSessionRequested(
    const AlwaysOnPduSessionRequested& apsr) {
  ie_always_on_pdu_session_requested_ =
      std::make_optional<AlwaysOnPduSessionRequested>(apsr);
}

//------------------------------------------------------------------------------
void PduSessionModificationRequest::GetAlwaysOnPduSessionRequested(
    std::optional<AlwaysOnPduSessionRequested>& apsr) const {
  apsr = ie_always_on_pdu_session_requested_;
}

//------------------------------------------------------------------------------
void PduSessionModificationRequest::SetIntegrityProtectionMaximumDataRate(
    const IntegrityProtectionMaximumDataRate& rate) {
  ie_integrity_protection_maximum_data_rate_ =
      std::make_optional<IntegrityProtectionMaximumDataRate>(rate);
}

//------------------------------------------------------------------------------
void PduSessionModificationRequest::GetIntegrityProtectionMaximumDataRate(
    std::optional<IntegrityProtectionMaximumDataRate>& rate) const {
  rate = ie_integrity_protection_maximum_data_rate_;
}

//------------------------------------------------------------------------------
void PduSessionModificationRequest::SetRequestedQosRules(
    const QosRules& qos_rules) {
  ie_requested_qos_rules_ = std::make_optional<QosRules>(qos_rules);
}

//------------------------------------------------------------------------------
void PduSessionModificationRequest::GetRequestedQosRules(
    std::optional<QosRules>& qos_rules) const {
  qos_rules = ie_requested_qos_rules_;
}

//------------------------------------------------------------------------------
void PduSessionModificationRequest::SetRequestedQosFlowDescriptions(
    const QosFlowDescriptions& flow_descriptions) {
  ie_requested_qos_flow_descriptions_ =
      std::make_optional<QosFlowDescriptions>(flow_descriptions);
}

//------------------------------------------------------------------------------
void PduSessionModificationRequest::GetRequestedQosFlowDescriptions(
    std::optional<QosFlowDescriptions>& flow_descriptions) const {
  flow_descriptions = ie_requested_qos_flow_descriptions_;
}

//------------------------------------------------------------------------------
void PduSessionModificationRequest::SetExtendedProtocolConfigurationOptions(
    const ExtendedProtocolConfigurationOptions& options) {
  ie_extended_protocol_configuration_options_ =
      std::make_optional<ExtendedProtocolConfigurationOptions>(options);
}

//------------------------------------------------------------------------------
void PduSessionModificationRequest::GetExtendedProtocolConfigurationOptions(
    std::optional<ExtendedProtocolConfigurationOptions>& options) const {
  options = ie_extended_protocol_configuration_options_;
}

//------------------------------------------------------------------------------
int PduSessionModificationRequest::Encode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Encoding PduSessionModificationRequest message");
  int encoded_size    = 0;
  int encoded_ie_size = 0;
  // Header
  if ((encoded_ie_size = Nas5gsmMessage::Encode(buf, len)) ==
      KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Encoding NAS Header error");
    return KEncodeDecodeError;
  }
  encoded_size += encoded_ie_size;

  // 5GSM capability
  if ((encoded_ie_size =
           NasHelper::Encode(ie_5gsm_capability_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // 5GSM cause
  if ((encoded_ie_size = NasHelper::Encode(
           ie_5gsm_cause_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // Maximum number of supported packet filters
  if ((encoded_ie_size = NasHelper::Encode(
           ie_maximum_number_of_supported_packet_filters_, buf, len,
           encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // Always-on PDU session requested
  if ((encoded_ie_size = NasHelper::Encode(
           ie_always_on_pdu_session_requested_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // Integrity protection maximum data rate
  if ((encoded_ie_size = NasHelper::Encode(
           ie_integrity_protection_maximum_data_rate_, buf, len,
           encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // Requested QoS rules
  if ((encoded_ie_size = NasHelper::Encode(
           ie_requested_qos_rules_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // Requested QoS flow descriptions
  if ((encoded_ie_size = NasHelper::Encode(
           ie_requested_qos_flow_descriptions_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // TODO: Mapped EPS bearer contexts
  // Extended protocol configuration options
  if ((encoded_ie_size = NasHelper::Encode(
           ie_extended_protocol_configuration_options_, buf, len,
           encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // TODO: Port management information container
  // TODO: Header compression configuration
  // TODO: Ethernet header compression configuration

  oai::logger::logger_common::nas().debug(
      "Encoded PduSessionModificationRequest message len (%d)", encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int PduSessionModificationRequest::Decode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Decoding PduSessionModificationRequest message");
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
    switch ((octet & 0xf0) >> 4) {
      case kIeiAlwaysOnPduSessionRequested: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiAlwaysOnPduSessionRequested);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_always_on_pdu_session_requested_, buf, len, decoded_size,
                 true)) == KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

      default: {
        flag = true;
      }
    }

    switch (octet) {
      case kIei5gsmCapability: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIei5gsmCapability);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_5gsm_capability_, buf, len, decoded_size, true)) ==
            KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

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

      case kIeiMaximumNumberOfSupportedPacketFilters: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiMaximumNumberOfSupportedPacketFilters);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_maximum_number_of_supported_packet_filters_, buf, len,
                 decoded_size, true)) == KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

      case kIeiAlwaysOnPduSessionRequested: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiAlwaysOnPduSessionRequested);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_always_on_pdu_session_requested_, buf, len, decoded_size,
                 true)) == KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

      case kIeiIntegrityProtectionMaximumDataRate: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiIntegrityProtectionMaximumDataRate);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_integrity_protection_maximum_data_rate_, buf, len,
                 decoded_size, true)) == KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

      case kIeiRequestedQosRules: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiRequestedQosRules);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_requested_qos_rules_, buf, len, decoded_size, true)) ==
            KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

      case kIeiRequestedQosFlowDescriptions: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiRequestedQosFlowDescriptions);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_requested_qos_flow_descriptions_, buf, len, decoded_size,
                 true)) == KEncodeDecodeError) {
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
      "Decoded PduSessionModificationRequest message len (%d)", decoded_size);
  return decoded_size;
}
