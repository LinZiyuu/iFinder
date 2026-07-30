/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionModificationCommand.hpp"

#include "NasHelper.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
PduSessionModificationCommand::PduSessionModificationCommand()
    : Nas5gsmMessage(
          k5gsSessionManagementMessages, kPduSessionModificationCommand) {
  ie_5gsm_cause_                              = std::nullopt;
  ie_session_ambr_                            = std::nullopt;
  ie_rq_timer_value_                          = std::nullopt;
  ie_always_on_pdu_session_indication_        = std::nullopt;
  ie_authorized_qos_rules_                    = std::nullopt;
  ie_authorized_qos_flow_descriptions_        = std::nullopt;
  ie_extended_protocol_configuration_options_ = std::nullopt;
}

//------------------------------------------------------------------------------
PduSessionModificationCommand::~PduSessionModificationCommand() {}

//------------------------------------------------------------------------------
uint32_t PduSessionModificationCommand::GetLength() const {
  uint32_t msg_len = 0;
  msg_len += Nas5gsmMessage::GetLength();

  if (ie_5gsm_cause_.has_value())
    msg_len += ie_5gsm_cause_.value().GetIeLength();
  if (ie_session_ambr_.has_value())
    msg_len += ie_session_ambr_.value().GetIeLength();
  if (ie_rq_timer_value_.has_value())
    msg_len += ie_rq_timer_value_.value().GetIeLength();
  if (ie_always_on_pdu_session_indication_.has_value())
    msg_len += ie_always_on_pdu_session_indication_.value().GetIeLength();
  if (ie_authorized_qos_rules_.has_value())
    msg_len += ie_authorized_qos_rules_.value().GetIeLength();
  if (ie_authorized_qos_flow_descriptions_.has_value())
    msg_len += ie_authorized_qos_flow_descriptions_.value().GetIeLength();
  if (ie_extended_protocol_configuration_options_.has_value())
    msg_len +=
        ie_extended_protocol_configuration_options_.value().GetIeLength();

  return msg_len;
}

//------------------------------------------------------------------------------
void PduSessionModificationCommand::Set5gsmCause(
    const _5gsmCause& _5gsm_cause) {
  ie_5gsm_cause_ = std::make_optional<_5gsmCause>(_5gsm_cause);
  ie_5gsm_cause_.value().SetIei(kIei5gsmCause);
}

//------------------------------------------------------------------------------
void PduSessionModificationCommand::Get5gsmCause(
    std::optional<_5gsmCause>& _5gsm_cause) const {
  _5gsm_cause = ie_5gsm_cause_;
}

void PduSessionModificationCommand::SetSessionAmbr(
    const SessionAmbr& session_ambr) {
  ie_session_ambr_ = std::make_optional<SessionAmbr>(session_ambr);
}

//------------------------------------------------------------------------------
void PduSessionModificationCommand::GetSessionAmbr(
    std::optional<SessionAmbr>& session_ambr) const {
  session_ambr = ie_session_ambr_;
}

//------------------------------------------------------------------------------
void PduSessionModificationCommand::SetRqTimerValue(
    const GprsTimer& rq_timer_value) {
  ie_rq_timer_value_ = std::make_optional<GprsTimer>(rq_timer_value);
}

//------------------------------------------------------------------------------
void PduSessionModificationCommand::GetRqTimerValue(
    std::optional<GprsTimer>& rq_timer_value) const {
  rq_timer_value = ie_rq_timer_value_;
}

//------------------------------------------------------------------------------
void PduSessionModificationCommand::SetAlwaysOnPduSessionIndication(
    const AlwaysOnPduSessionIndication& always_on_pdu_session_indication) {
  ie_always_on_pdu_session_indication_ =
      std::make_optional<AlwaysOnPduSessionIndication>(
          always_on_pdu_session_indication);
}

//------------------------------------------------------------------------------
void PduSessionModificationCommand::GetAlwaysOnPduSessionIndication(
    std::optional<AlwaysOnPduSessionIndication>&
        always_on_pdu_session_indication) const {
  always_on_pdu_session_indication = ie_always_on_pdu_session_indication_;
}

//------------------------------------------------------------------------------
void PduSessionModificationCommand::SetAuthorizedQosRules(
    const QosRules& qos_rules) {
  ie_authorized_qos_rules_ = std::make_optional<QosRules>(qos_rules);
}

//------------------------------------------------------------------------------
void PduSessionModificationCommand::GetAuthorizedQosRules(
    std::optional<QosRules>& qos_rules) const {
  qos_rules = ie_authorized_qos_rules_;
}

//------------------------------------------------------------------------------
void PduSessionModificationCommand::SetAuthorizedQosFlowDescriptions(
    const QosFlowDescriptions& flow_descriptions) {
  ie_authorized_qos_flow_descriptions_ =
      std::make_optional<QosFlowDescriptions>(flow_descriptions);
}

//------------------------------------------------------------------------------
void PduSessionModificationCommand::GetAuthorizedQosFlowDescriptions(
    std::optional<QosFlowDescriptions>& flow_descriptions) const {
  flow_descriptions = ie_authorized_qos_flow_descriptions_;
}

//------------------------------------------------------------------------------
void PduSessionModificationCommand::SetExtendedProtocolConfigurationOptions(
    const ExtendedProtocolConfigurationOptions& options) {
  ie_extended_protocol_configuration_options_ =
      std::make_optional<ExtendedProtocolConfigurationOptions>(options);
}

//------------------------------------------------------------------------------
void PduSessionModificationCommand::GetExtendedProtocolConfigurationOptions(
    std::optional<ExtendedProtocolConfigurationOptions>& options) const {
  options = ie_extended_protocol_configuration_options_;
}

//------------------------------------------------------------------------------
int PduSessionModificationCommand::Encode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Encoding PduSessionModificationCommand message");
  int encoded_size    = 0;
  int encoded_ie_size = 0;
  // Header
  if ((encoded_ie_size = Nas5gsmMessage::Encode(buf, len)) ==
      KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Encoding NAS Header error");
    return KEncodeDecodeError;
  }
  encoded_size += encoded_ie_size;

  // 5GSM Cause
  if ((encoded_ie_size = NasHelper::Encode(
           ie_5gsm_cause_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // Session AMBR
  if ((encoded_ie_size = NasHelper::Encode(
           ie_session_ambr_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // RQ timer value
  if ((encoded_ie_size = NasHelper::Encode(
           ie_rq_timer_value_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // Always-on PDU session indication
  if ((encoded_ie_size = NasHelper::Encode(
           ie_always_on_pdu_session_indication_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // Authorized QoS rules
  if ((encoded_ie_size = NasHelper::Encode(
           ie_authorized_qos_rules_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // TODO: Mapped EPS bearer contexts

  // Authorized QoS flow descriptions
  if ((encoded_ie_size = NasHelper::Encode(
           ie_authorized_qos_flow_descriptions_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // Extended protocol configuration options
  if ((encoded_ie_size = NasHelper::Encode(
           ie_extended_protocol_configuration_options_, buf, len,
           encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // TODO: ATSSS container
  // TODO: IP header compression configuration
  // TODO: Port management information container
  // TODO: Serving PLMN rate control
  // TODO: Ethernet header compression configuration

  oai::logger::logger_common::nas().debug(
      "Encoded PduSessionModificationCommand message len (%d)", encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int PduSessionModificationCommand::Decode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Decoding PduSessionModificationCommand message");
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
      case kIeiAlwaysOnPduSessionIndication: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiAlwaysOnPduSessionIndication);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_always_on_pdu_session_indication_, buf, len, decoded_size,
                 true)) == KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;
        // TODO: Control plane only indication

      default: {
        flag = true;
      }
    }

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

      case kIeiSessionAmbr: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiSessionAmbr);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_session_ambr_, buf, len, decoded_size, true)) ==
            KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

      case kIeiRqTimerValue: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiRqTimerValue);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_rq_timer_value_, kIeiRqTimerValue, buf, len, decoded_size,
                 true)) == KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

      case kIeiAuthorizedQosRules: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiAuthorizedQosRules);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_authorized_qos_rules_, buf, len, decoded_size, true)) ==
            KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

      case kIeiAuthorizedQosFlowDescriptions: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiAuthorizedQosFlowDescriptions);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_authorized_qos_flow_descriptions_, buf, len, decoded_size,
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

        // TODO: ATSSS container
        // TODO: IP header compression configuration
        // TODO: Port management information container
        // TODO: Serving PLMN rate control
        // TODO: Ethernet header compression configuration

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
      "Decoded PduSessionModificationCommand message len (%d)", decoded_size);
  return decoded_size;
}
