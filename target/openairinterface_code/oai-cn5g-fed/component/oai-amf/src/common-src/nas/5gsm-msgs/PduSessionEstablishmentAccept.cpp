/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionEstablishmentAccept.hpp"

#include "NasHelper.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
PduSessionEstablishmentAccept::PduSessionEstablishmentAccept()
    : Nas5gsmMessage(
          k5gsSessionManagementMessages, kPduSessionEstablishmentAccept) {
  ie_5gsm_cause_                              = std::nullopt;
  ie_pdu_address_                             = std::nullopt;
  ie_gprs_timer_                              = std::nullopt;
  ie_s_nssai_                                 = std::nullopt;
  ie_always_on_pdu_session_indication_        = std::nullopt;
  ie_eap_message_                             = std::nullopt;
  ie_authorized_qos_flow_descriptions_        = std::nullopt;
  ie_extended_protocol_configuration_options_ = std::nullopt;
  ie_dnn_                                     = std::nullopt;
}

//------------------------------------------------------------------------------
PduSessionEstablishmentAccept::~PduSessionEstablishmentAccept() {}

//------------------------------------------------------------------------------
uint32_t PduSessionEstablishmentAccept::GetLength() const {
  uint32_t msg_len = 0;
  msg_len += Nas5gsmMessage::GetLength();
  // msg_len += ie_selected_pdu_session_type_.GetIeLength();
  // msg_len += ie_selected_ssc_mode_.GetIeLength();
  msg_len += 1;  // 1/2 octet for Selected PDU session type and 1/2 octet for
                 // Selected SSC mode
  msg_len += ie_authorized_qos_rules_.GetIeLength();
  msg_len += ie_session_ambr_.GetIeLength();

  if (ie_5gsm_cause_.has_value())
    msg_len += ie_5gsm_cause_.value().GetIeLength();

  if (ie_pdu_address_.has_value())
    msg_len += ie_pdu_address_.value().GetIeLength();

  if (ie_gprs_timer_.has_value())
    msg_len += ie_gprs_timer_.value().GetIeLength();

  if (ie_s_nssai_.has_value()) msg_len += ie_s_nssai_.value().GetIeLength();

  if (ie_always_on_pdu_session_indication_.has_value())
    msg_len += ie_always_on_pdu_session_indication_.value().GetIeLength();

  if (ie_eap_message_.has_value())
    msg_len += ie_eap_message_.value().GetIeLength();

  if (ie_authorized_qos_flow_descriptions_.has_value())
    msg_len += ie_authorized_qos_flow_descriptions_.value().GetIeLength();

  if (ie_extended_protocol_configuration_options_.has_value())
    msg_len +=
        ie_extended_protocol_configuration_options_.value().GetIeLength();

  if (ie_dnn_.has_value()) msg_len += ie_dnn_.value().GetIeLength();

  return msg_len;
}

//------------------------------------------------------------------------------
void PduSessionEstablishmentAccept::SetSelectedPduSessionType(
    const PduSessionType& pdu_session_type) {
  ie_selected_pdu_session_type_ = pdu_session_type;
}

//------------------------------------------------------------------------------
void PduSessionEstablishmentAccept::GetSelectedPduSessionType(
    PduSessionType& pdu_session_type) const {
  pdu_session_type = ie_selected_pdu_session_type_;
}

//------------------------------------------------------------------------------
void PduSessionEstablishmentAccept::SetSelectedSscMode(
    const SscMode& ssc_mode) {
  ie_selected_ssc_mode_ = ssc_mode;
}

//------------------------------------------------------------------------------
void PduSessionEstablishmentAccept::GetSelectedSscMode(
    SscMode& ssc_mode) const {
  ssc_mode = ie_selected_ssc_mode_;
}

//------------------------------------------------------------------------------
void PduSessionEstablishmentAccept::SetAuthorizedQosRules(
    const QosRules& qos_rules) {
  ie_authorized_qos_rules_ = qos_rules;
}

//------------------------------------------------------------------------------
void PduSessionEstablishmentAccept::GetAuthorizedQosRules(
    QosRules& qos_rules) const {
  qos_rules = ie_authorized_qos_rules_;
}

//------------------------------------------------------------------------------
void PduSessionEstablishmentAccept::SetSessionAmbr(
    const SessionAmbr& session_ambr) {
  ie_session_ambr_ = session_ambr;
}

//------------------------------------------------------------------------------
void PduSessionEstablishmentAccept::GetSessionAmbr(
    SessionAmbr& session_ambr) const {
  session_ambr = ie_session_ambr_;
}

//------------------------------------------------------------------------------
void PduSessionEstablishmentAccept::Set5gsmCause(
    const _5gsmCause& _5gsm_cause) {
  ie_5gsm_cause_ = std::make_optional<_5gsmCause>(_5gsm_cause);
  ie_5gsm_cause_.value().SetIei(kIei5gsmCause);
}

//------------------------------------------------------------------------------
void PduSessionEstablishmentAccept::Get5gsmCause(
    std::optional<_5gsmCause>& _5gsm_cause) const {
  _5gsm_cause = ie_5gsm_cause_;
}

//------------------------------------------------------------------------------
void PduSessionEstablishmentAccept::SetPduAddress(
    const PduAddress& pdu_address) {
  ie_pdu_address_ = std::make_optional<PduAddress>(pdu_address);
}

//------------------------------------------------------------------------------
void PduSessionEstablishmentAccept::GetPduAddress(
    std::optional<PduAddress>& pdu_address) const {
  pdu_address = ie_pdu_address_;
}

//------------------------------------------------------------------------------
void PduSessionEstablishmentAccept::SetRqTimerValue(
    const GprsTimer& gprs_timer) {
  ie_gprs_timer_ = std::make_optional<GprsTimer>(gprs_timer);
}

//------------------------------------------------------------------------------
void PduSessionEstablishmentAccept::GetRqTimerValue(
    std::optional<GprsTimer>& gprs_timer) const {
  gprs_timer = ie_gprs_timer_;
}

//------------------------------------------------------------------------------
void PduSessionEstablishmentAccept::SetSNssai(const SNssai& snssai) {
  ie_s_nssai_ = std::make_optional<SNssai>(snssai);
}

//------------------------------------------------------------------------------
void PduSessionEstablishmentAccept::GetSNssai(
    std::optional<SNssai>& snssai) const {
  snssai = ie_s_nssai_;
}

//------------------------------------------------------------------------------
void PduSessionEstablishmentAccept::SetAlwaysOnPduSessionIndication(
    const AlwaysOnPduSessionIndication& always_on_pdu_session_indication) {
  ie_always_on_pdu_session_indication_ =
      std::make_optional<AlwaysOnPduSessionIndication>(
          always_on_pdu_session_indication);
}

//------------------------------------------------------------------------------
void PduSessionEstablishmentAccept::GetAlwaysOnPduSessionIndication(
    std::optional<AlwaysOnPduSessionIndication>&
        always_on_pdu_session_indication) const {
  always_on_pdu_session_indication = ie_always_on_pdu_session_indication_;
}

//------------------------------------------------------------------------------
void PduSessionEstablishmentAccept::SetEapMessage(
    const EapMessage& eap_message) {
  ie_eap_message_ = std::make_optional<EapMessage>(eap_message);
}

//------------------------------------------------------------------------------
void PduSessionEstablishmentAccept::GetEapMessage(
    std::optional<EapMessage>& eap_message) const {
  eap_message = ie_eap_message_;
}

//------------------------------------------------------------------------------
void PduSessionEstablishmentAccept::SetAuthorizedQosFlowDescriptions(
    const QosFlowDescriptions& flow_descriptions) {
  ie_authorized_qos_flow_descriptions_ =
      std::make_optional<QosFlowDescriptions>(flow_descriptions);
}

//------------------------------------------------------------------------------
void PduSessionEstablishmentAccept::GetAuthorizedQosFlowDescriptions(
    std::optional<QosFlowDescriptions>& flow_descriptions) const {
  flow_descriptions = ie_authorized_qos_flow_descriptions_;
}

//------------------------------------------------------------------------------
void PduSessionEstablishmentAccept::SetExtendedProtocolConfigurationOptions(
    const ExtendedProtocolConfigurationOptions& options) {
  ie_extended_protocol_configuration_options_ =
      std::make_optional<ExtendedProtocolConfigurationOptions>(options);
}

//------------------------------------------------------------------------------
void PduSessionEstablishmentAccept::GetExtendedProtocolConfigurationOptions(
    std::optional<ExtendedProtocolConfigurationOptions>& options) const {
  options = ie_extended_protocol_configuration_options_;
}

//------------------------------------------------------------------------------
void PduSessionEstablishmentAccept::SetDnn(const Dnn& dnn) {
  ie_dnn_ = std::make_optional<Dnn>(dnn);
}

//------------------------------------------------------------------------------
void PduSessionEstablishmentAccept::GetDnn(std::optional<Dnn>& dnn) const {
  dnn = ie_dnn_;
}

//------------------------------------------------------------------------------
int PduSessionEstablishmentAccept::Encode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Encoding PduSessionEstablishmentAccept message");
  int encoded_size    = 0;
  int encoded_ie_size = 0;
  // Header
  if ((encoded_ie_size = Nas5gsmMessage::Encode(buf, len)) ==
      KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Encoding NAS Header error");
    return KEncodeDecodeError;
  }
  encoded_size += encoded_ie_size;

  // Selected PDU session type
  if ((encoded_ie_size = NasHelper::Encode(
           ie_selected_pdu_session_type_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // Selected SSC mode
  if ((encoded_ie_size =
           NasHelper::Encode(ie_selected_ssc_mode_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }
  encoded_size++;  // 1/2 forSelected PDU session type, 1/2 octet for Selected
                   // SSC mode

  // Authorized QoS rules
  if ((encoded_ie_size = NasHelper::Encode(
           ie_authorized_qos_rules_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // Session AMBR
  if ((encoded_ie_size = NasHelper::Encode(
           ie_session_ambr_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // 5GSM cause
  if ((encoded_ie_size = NasHelper::Encode(
           ie_5gsm_cause_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // PDU address
  if ((encoded_ie_size = NasHelper::Encode(
           ie_pdu_address_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // RQ timer value
  if ((encoded_ie_size = NasHelper::Encode(
           ie_gprs_timer_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // S-NSSAI
  if ((encoded_ie_size = NasHelper::Encode(
           ie_s_nssai_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // Always-on PDU session indication
  if ((encoded_ie_size = NasHelper::Encode(
           ie_always_on_pdu_session_indication_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // TODO: Mapped EPS bearer contexts

  // EAP message
  if ((encoded_ie_size = NasHelper::Encode(
           ie_eap_message_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

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

  // DNN
  if ((encoded_ie_size = NasHelper::Encode(ie_dnn_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // TODO: 5GSM network feature support
  // TODO: Serving PLMN rate control
  // TODO: ATSSS container
  // TODO: Control plane only indication
  // TODO: IP header compression configuration
  // TODO: Ethernet header compression configuration

  oai::logger::logger_common::nas().debug(
      "Encoded PduSessionEstablishmentAccept message len (%d)", encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int PduSessionEstablishmentAccept::Decode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Decoding PduSessionEstablishmentAccept message");
  int decoded_size    = 0;
  int decoded_ie_size = 0;

  // Header
  decoded_ie_size = Nas5gsmMessage::Decode(buf, len);
  if (decoded_ie_size == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Decoding NAS Header error");
    return KEncodeDecodeError;
  }
  decoded_size += decoded_ie_size;

  // Selected PDU session type
  if ((decoded_ie_size = NasHelper::Decode(
           ie_selected_pdu_session_type_, buf, len, decoded_size, false)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // Selected SSC mode
  if ((decoded_ie_size = NasHelper::Decode(
           ie_selected_ssc_mode_, buf, len, decoded_size, false)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // Authorized QoS rules
  if ((decoded_ie_size = NasHelper::Decode(
           ie_authorized_qos_rules_, buf, len, decoded_size, false)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // Session AMBR
  if ((decoded_ie_size = NasHelper::Decode(
           ie_session_ambr_, buf, len, decoded_size, false)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

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

      case kIeiPduAddress: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiPduAddress);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_pdu_address_, buf, len, decoded_size, true)) ==
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
                 ie_gprs_timer_, kIeiRqTimerValue, buf, len, decoded_size,
                 true)) == KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

      case kIeiSNssai: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiSNssai);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_s_nssai_, kIeiSNssai, buf, len, decoded_size, true)) ==
            KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

      case kIeiEapMessage: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiEapMessage);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_eap_message_, buf, len, decoded_size, true)) ==
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

      case kIeiDnn: {
        oai::logger::logger_common::nas().debug("Decoding IEI 0x%x", kIeiDnn);
        if ((decoded_ie_size =
                 NasHelper::Decode(ie_dnn_, buf, len, decoded_size, true)) ==
            KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

        // TODO: 5GSM network feature support
        // TODO: Serving PLMN rate control
        // TODO: ATSSS container
        // TODO: Control plane only indication
        // TODO: IP header compression configuration
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
      "Decoded PduSessionEstablishmentAccept message len (%d)", decoded_size);
  return decoded_size;
}
