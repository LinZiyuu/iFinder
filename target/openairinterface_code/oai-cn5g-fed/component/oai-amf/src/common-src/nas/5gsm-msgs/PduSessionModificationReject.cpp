/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionModificationReject.hpp"

#include "NasHelper.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
PduSessionModificationReject::PduSessionModificationReject()
    : Nas5gsmMessage(
          k5gsSessionManagementMessages, kPduSessionModificationReject) {
  ie_back_off_timer_value_                    = std::nullopt;
  ie_5gsm_congestion_re_attempt_indicator_    = std::nullopt;
  ie_extended_protocol_configuration_options_ = std::nullopt;
  ie_re_attempt_indicator_                    = std::nullopt;
}

//------------------------------------------------------------------------------
PduSessionModificationReject::~PduSessionModificationReject() {}

//------------------------------------------------------------------------------
uint32_t PduSessionModificationReject::GetLength() const {
  uint32_t msg_len = 0;
  msg_len += Nas5gsmMessage::GetLength();
  msg_len += ie_5gsm_cause_.GetIeLength();

  if (ie_back_off_timer_value_.has_value())
    msg_len += ie_back_off_timer_value_.value().GetIeLength();
  if (ie_5gsm_congestion_re_attempt_indicator_.has_value())
    msg_len += ie_5gsm_congestion_re_attempt_indicator_.value().GetIeLength();
  if (ie_extended_protocol_configuration_options_.has_value())
    msg_len +=
        ie_extended_protocol_configuration_options_.value().GetIeLength();
  if (ie_re_attempt_indicator_.has_value())
    msg_len += ie_re_attempt_indicator_.value().GetIeLength();

  return msg_len;
}

//------------------------------------------------------------------------------
void PduSessionModificationReject::Set5gsmCause(const _5gsmCause& _5gsm_cause) {
  ie_5gsm_cause_ = _5gsm_cause;
}

//------------------------------------------------------------------------------
void PduSessionModificationReject::Get5gsmCause(_5gsmCause& _5gsm_cause) const {
  _5gsm_cause = ie_5gsm_cause_;
}

//------------------------------------------------------------------------------
void PduSessionModificationReject::SetBackOffTimerValue(
    const GprsTimer3& back_off_timer_value) {
  ie_back_off_timer_value_ =
      std::make_optional<GprsTimer3>(back_off_timer_value);
}

//------------------------------------------------------------------------------
void PduSessionModificationReject::GetBackOffTimerValue(
    std::optional<GprsTimer3>& back_off_timer_value) const {
  back_off_timer_value = ie_back_off_timer_value_;
}

//------------------------------------------------------------------------------
void PduSessionModificationReject::Set5gsmCongestionReAttemptIndicator(
    const _5gsmCongestionReAttemptIndicator& indicator) {
  ie_5gsm_congestion_re_attempt_indicator_ =
      std::make_optional<_5gsmCongestionReAttemptIndicator>(indicator);
}

//------------------------------------------------------------------------------
void PduSessionModificationReject::Get5gsmCongestionReAttemptIndicator(
    std::optional<_5gsmCongestionReAttemptIndicator>& indicator) const {
  indicator = ie_5gsm_congestion_re_attempt_indicator_;
}

//------------------------------------------------------------------------------
void PduSessionModificationReject::SetExtendedProtocolConfigurationOptions(
    const ExtendedProtocolConfigurationOptions& options) {
  ie_extended_protocol_configuration_options_ =
      std::make_optional<ExtendedProtocolConfigurationOptions>(options);
}

//------------------------------------------------------------------------------
void PduSessionModificationReject::GetExtendedProtocolConfigurationOptions(
    std::optional<ExtendedProtocolConfigurationOptions>& options) const {
  options = ie_extended_protocol_configuration_options_;
}

//------------------------------------------------------------------------------
void PduSessionModificationReject::SetReAttemptIndicator(
    const ReAttemptIndicator& re_attempt_indicator) {
  ie_re_attempt_indicator_ =
      std::make_optional<ReAttemptIndicator>(re_attempt_indicator);
}

//------------------------------------------------------------------------------
void PduSessionModificationReject::GetReAttemptIndicator(
    std::optional<ReAttemptIndicator>& re_attempt_indicator) const {
  re_attempt_indicator = ie_re_attempt_indicator_;
}

//------------------------------------------------------------------------------
int PduSessionModificationReject::Encode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Encoding PduSessionModificationReject message");
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

  // Re-attempt indicator
  if ((encoded_ie_size = NasHelper::Encode(
           ie_re_attempt_indicator_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  oai::logger::logger_common::nas().debug(
      "Encoded PduSessionModificationReject message len (%d)", encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int PduSessionModificationReject::Decode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Decoding PduSessionModificationReject message");
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

      case kIeiReAttemptIndicator: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiReAttemptIndicator);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_re_attempt_indicator_, buf, len, decoded_size, true)) ==
            KEncodeDecodeError) {
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
      "Decoded PduSessionModificationReject message len (%d)", decoded_size);
  return decoded_size;
}
