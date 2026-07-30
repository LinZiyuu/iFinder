/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionReleaseCommand.hpp"

#include "NasHelper.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
PduSessionReleaseCommand::PduSessionReleaseCommand()
    : Nas5gsmMessage(k5gsSessionManagementMessages, kPduSessionReleaseCommand) {
  ie_back_off_timer_value_                    = std::nullopt;
  ie_eap_message_                             = std::nullopt;
  ie_5gsm_congestion_re_attempt_indicator_    = std::nullopt;
  ie_extended_protocol_configuration_options_ = std::nullopt;
}

//------------------------------------------------------------------------------
PduSessionReleaseCommand::~PduSessionReleaseCommand() {}

//------------------------------------------------------------------------------
uint32_t PduSessionReleaseCommand::GetLength() const {
  uint32_t msg_len = 0;
  msg_len += Nas5gsmMessage::GetLength();
  msg_len += ie_5gsm_cause_.GetIeLength();

  if (ie_back_off_timer_value_.has_value())
    msg_len += ie_back_off_timer_value_.value().GetIeLength();
  if (ie_eap_message_.has_value())
    msg_len += ie_eap_message_.value().GetIeLength();
  if (ie_5gsm_congestion_re_attempt_indicator_.has_value())
    msg_len += ie_5gsm_congestion_re_attempt_indicator_.value().GetIeLength();
  if (ie_extended_protocol_configuration_options_.has_value())
    msg_len +=
        ie_extended_protocol_configuration_options_.value().GetIeLength();

  return msg_len;
}

//------------------------------------------------------------------------------
void PduSessionReleaseCommand::Set5gsmCause(const _5gsmCause& _5gsm_cause) {
  ie_5gsm_cause_ = _5gsm_cause;
}

//------------------------------------------------------------------------------
void PduSessionReleaseCommand::Get5gsmCause(_5gsmCause& _5gsm_cause) const {
  _5gsm_cause = ie_5gsm_cause_;
}

//------------------------------------------------------------------------------
void PduSessionReleaseCommand::SetBackOffTimerValue(
    const GprsTimer3& back_off_timer_value) {
  ie_back_off_timer_value_ =
      std::make_optional<GprsTimer3>(back_off_timer_value);
}

//------------------------------------------------------------------------------
void PduSessionReleaseCommand::GetBackOffTimerValue(
    std::optional<GprsTimer3>& back_off_timer_value) const {
  back_off_timer_value = ie_back_off_timer_value_;
}

//------------------------------------------------------------------------------
void PduSessionReleaseCommand::SetEapMessage(const EapMessage& eap_message) {
  ie_eap_message_ = std::make_optional<EapMessage>(eap_message);
}

//------------------------------------------------------------------------------
void PduSessionReleaseCommand::GetEapMessage(
    std::optional<EapMessage>& eap_message) const {
  eap_message = ie_eap_message_;
}

//------------------------------------------------------------------------------
void PduSessionReleaseCommand::Set5gsmCongestionReAttemptIndicator(
    const _5gsmCongestionReAttemptIndicator& indicator) {
  ie_5gsm_congestion_re_attempt_indicator_ =
      std::make_optional<_5gsmCongestionReAttemptIndicator>(indicator);
}

//------------------------------------------------------------------------------
void PduSessionReleaseCommand::Get5gsmCongestionReAttemptIndicator(
    std::optional<_5gsmCongestionReAttemptIndicator>& indicator) const {
  indicator = ie_5gsm_congestion_re_attempt_indicator_;
}

//------------------------------------------------------------------------------
void PduSessionReleaseCommand::SetExtendedProtocolConfigurationOptions(
    const ExtendedProtocolConfigurationOptions& options) {
  ie_extended_protocol_configuration_options_ =
      std::make_optional<ExtendedProtocolConfigurationOptions>(options);
}

//------------------------------------------------------------------------------
void PduSessionReleaseCommand::GetExtendedProtocolConfigurationOptions(
    std::optional<ExtendedProtocolConfigurationOptions>& options) const {
  options = ie_extended_protocol_configuration_options_;
}

//------------------------------------------------------------------------------
int PduSessionReleaseCommand::Encode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Encoding PduSessionReleaseCommand message");
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

  // Back-off timer value
  if ((encoded_ie_size = NasHelper::Encode(
           ie_back_off_timer_value_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // EAP message
  if ((encoded_ie_size = NasHelper::Encode(
           ie_eap_message_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // 5GSM congestion re-attempt indicator
  if ((encoded_ie_size = NasHelper::Encode(
           ie_5gsm_congestion_re_attempt_indicator_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // Extended protocol configuration options
  if ((encoded_ie_size = NasHelper::Encode(
           ie_extended_protocol_configuration_options_, buf, len,
           encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  oai::logger::logger_common::nas().debug(
      "Encoded PduSessionReleaseCommand message len (%d)", encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int PduSessionReleaseCommand::Decode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Decoding PduSessionReleaseCommand message");
  int decoded_size    = 0;
  int decoded_ie_size = 0;

  // Header
  decoded_ie_size = Nas5gsmMessage::Decode(buf, len);
  if (decoded_ie_size == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Decoding NAS Header error");
    return KEncodeDecodeError;
  }
  decoded_size += decoded_ie_size;

  // 5GSM Cause
  if ((decoded_ie_size =
           NasHelper::Decode(ie_5gsm_cause_, buf, len, decoded_size, false)) ==
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
      case kIeiGprsTimer3BackOffTimer: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiGprsTimer3BackOffTimer);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_back_off_timer_value_, kIeiGprsTimer3BackOffTimer, buf, len,
                 decoded_size, true)) == KEncodeDecodeError) {
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

      case kIei5gsmCongestionReAttemptIndicator: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIei5gsmCongestionReAttemptIndicator);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_5gsm_congestion_re_attempt_indicator_, buf, len,
                 decoded_size, true)) == KEncodeDecodeError) {
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
      "Decoded PduSessionReleaseCommand message len (%d)", decoded_size);
  return decoded_size;
}
