/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionEstablishmentRequest.hpp"

#include "NasHelper.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
PduSessionEstablishmentRequest::PduSessionEstablishmentRequest()
    : Nas5gsmMessage(
          k5gsSessionManagementMessages, kPduSessionEstablishmentRequest) {
  ie_pdu_session_type_                           = std::nullopt;
  ie_ssc_mode_                                   = std::nullopt;
  ie_5gsm_capability_                            = std::nullopt;
  ie_maximum_number_of_supported_packet_filters_ = std::nullopt;
  ie_always_on_pdu_session_requested_            = std::nullopt;
  ie_pdu_dn_request_container_                   = std::nullopt;
  ie_extended_protocol_configuration_options_    = std::nullopt;
  ie_ip_header_compression_configuration_        = std::nullopt;
}

//------------------------------------------------------------------------------
PduSessionEstablishmentRequest::~PduSessionEstablishmentRequest() {}

uint32_t PduSessionEstablishmentRequest::GetLength() const {
  uint32_t msg_len = 0;
  msg_len += Nas5gsmMessage::GetLength();
  msg_len += ie_integrity_protection_maximum_data_rate_.GetIeLength();
  if (ie_pdu_session_type_.has_value())
    msg_len += ie_pdu_session_type_.value().GetIeLength();
  if (ie_ssc_mode_.has_value()) msg_len += ie_ssc_mode_.value().GetIeLength();
  if (ie_5gsm_capability_.has_value())
    msg_len += ie_5gsm_capability_.value().GetIeLength();
  if (ie_maximum_number_of_supported_packet_filters_.has_value())
    msg_len +=
        ie_maximum_number_of_supported_packet_filters_.value().GetIeLength();
  if (ie_always_on_pdu_session_requested_.has_value())
    msg_len += ie_always_on_pdu_session_requested_.value().GetIeLength();
  if (ie_pdu_dn_request_container_.has_value())
    msg_len += ie_pdu_dn_request_container_.value().GetIeLength();
  if (ie_extended_protocol_configuration_options_.has_value())
    msg_len +=
        ie_extended_protocol_configuration_options_.value().GetIeLength();
  if (ie_ip_header_compression_configuration_.has_value())
    msg_len += ie_ip_header_compression_configuration_.value().GetIeLength();
  return msg_len;
}

//------------------------------------------------------------------------------
void PduSessionEstablishmentRequest::SetPduSessionIdentity(
    uint8_t pdu_session_id) {
  ie_header_.SetPduSessionIdentity(pdu_session_id);
}

//------------------------------------------------------------------------------
uint8_t PduSessionEstablishmentRequest::GetPduSessionIdentity() const {
  return ie_header_.GetPduSessionIdentity();
}

//------------------------------------------------------------------------------
void PduSessionEstablishmentRequest::SetProcedureTransactionIdentity(
    uint16_t procedure_transaction_id) {
  ie_header_.SetProcedureTransactionIdentity(procedure_transaction_id);
}

//------------------------------------------------------------------------------
uint16_t PduSessionEstablishmentRequest::GetProcedureTransactionIdentity()
    const {
  return ie_header_.GetProcedureTransactionIdentity();
}

//------------------------------------------------------------------------------
void PduSessionEstablishmentRequest::SetIntegrityProtectionMaximumDataRate(
    const IntegrityProtectionMaximumDataRate& rate) {
  ie_integrity_protection_maximum_data_rate_ = rate;
}

//------------------------------------------------------------------------------
IntegrityProtectionMaximumDataRate
PduSessionEstablishmentRequest::GetIntegrityProtectionMaximumDataRate() const {
  return ie_integrity_protection_maximum_data_rate_;
}

//------------------------------------------------------------------------------
void PduSessionEstablishmentRequest::SetPduSessionType(
    const PduSessionType& type) {
  ie_pdu_session_type_ = std::make_optional<PduSessionType>(type);
}

//------------------------------------------------------------------------------
std::optional<PduSessionType>
PduSessionEstablishmentRequest::GetPduSessionType() const {
  return ie_pdu_session_type_;
}

//------------------------------------------------------------------------------
void PduSessionEstablishmentRequest::SetSscMode(const SscMode ssc_mode) {
  ie_ssc_mode_ = std::make_optional<SscMode>(ssc_mode);
}

//------------------------------------------------------------------------------
std::optional<SscMode> PduSessionEstablishmentRequest::GetSscMode() const {
  return ie_ssc_mode_;
}

//------------------------------------------------------------------------------
void PduSessionEstablishmentRequest::Set5gsmCapability(
    const _5gsmCapability& _5gsm_capability) {
  ie_5gsm_capability_ = std::make_optional<_5gsmCapability>(_5gsm_capability);
}

//------------------------------------------------------------------------------
std::optional<_5gsmCapability>
PduSessionEstablishmentRequest::Get5gsmCapability() const {
  return ie_5gsm_capability_;
}

//------------------------------------------------------------------------------
void PduSessionEstablishmentRequest::SetMaximumNumberOfSupportedPacketFilters(
    const MaximumNumberOfSupportedPacketFilters& filters) {
  ie_maximum_number_of_supported_packet_filters_ =
      std::make_optional<MaximumNumberOfSupportedPacketFilters>(filters);
}

//------------------------------------------------------------------------------
std::optional<MaximumNumberOfSupportedPacketFilters>
PduSessionEstablishmentRequest::GetMaximumNumberOfSupportedPacketFilters() {
  return ie_maximum_number_of_supported_packet_filters_;
}

//------------------------------------------------------------------------------
void PduSessionEstablishmentRequest::SetAlwaysOnPduSessionRequested(
    const AlwaysOnPduSessionRequested& apsr) {
  ie_always_on_pdu_session_requested_ =
      std::make_optional<AlwaysOnPduSessionRequested>(apsr);
}

//------------------------------------------------------------------------------
std::optional<AlwaysOnPduSessionRequested>
PduSessionEstablishmentRequest::GetAlwaysOnPduSessionRequested() const {
  return ie_always_on_pdu_session_requested_;
}

//------------------------------------------------------------------------------
void PduSessionEstablishmentRequest::SetPduDnRequestContainer(
    const PduDnRequestContainer& container) {
  ie_pdu_dn_request_container_ =
      std::make_optional<PduDnRequestContainer>(container);
}

//------------------------------------------------------------------------------
std::optional<PduDnRequestContainer>
PduSessionEstablishmentRequest::GetPduDnRequestContainer() const {
  return ie_pdu_dn_request_container_;
}

//------------------------------------------------------------------------------
void PduSessionEstablishmentRequest::SetExtendedProtocolConfigurationOptions(
    const ExtendedProtocolConfigurationOptions& options) {
  ie_extended_protocol_configuration_options_ =
      std::make_optional<ExtendedProtocolConfigurationOptions>(options);
}

//------------------------------------------------------------------------------
std::optional<ExtendedProtocolConfigurationOptions>
PduSessionEstablishmentRequest::GetExtendedProtocolConfigurationOptions()
    const {
  return ie_extended_protocol_configuration_options_;
}

//------------------------------------------------------------------------------
void PduSessionEstablishmentRequest::SetIpHeaderCompressionConfiguration(
    const IpHeaderCompressionConfiguration& configuration) {
  ie_ip_header_compression_configuration_ =
      std::make_optional<IpHeaderCompressionConfiguration>(configuration);
}

//------------------------------------------------------------------------------
std::optional<IpHeaderCompressionConfiguration>
PduSessionEstablishmentRequest::GetIpHeaderCompressionConfiguration() const {
  return ie_ip_header_compression_configuration_;
}

//------------------------------------------------------------------------------
int PduSessionEstablishmentRequest::Encode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Encoding PduSessionEstablishmentRequest message");
  int encoded_size    = 0;
  int encoded_ie_size = 0;
  // Header
  if ((encoded_ie_size = Nas5gsmMessage::Encode(buf, len)) ==
      KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Encoding NAS Header error");
    return KEncodeDecodeError;
  }
  encoded_size += encoded_ie_size;

  // Integrity protection maximum data rate
  if ((encoded_ie_size = NasHelper::Encode(
           ie_integrity_protection_maximum_data_rate_, buf, len,
           encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // PDU session type
  if ((encoded_ie_size =
           NasHelper::Encode(ie_pdu_session_type_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // SSC mode
  if ((encoded_ie_size = NasHelper::Encode(
           ie_ssc_mode_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // 5GSM capability
  if ((encoded_ie_size =
           NasHelper::Encode(ie_5gsm_capability_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
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

  // SM PDU DN request container
  if ((encoded_ie_size = NasHelper::Encode(
           ie_pdu_dn_request_container_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // Extended protocol configuration options
  if ((encoded_ie_size = NasHelper::Encode(
           ie_extended_protocol_configuration_options_, buf, len,
           encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // IP header compression configuration
  if ((encoded_ie_size = NasHelper::Encode(
           ie_ip_header_compression_configuration_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // TODO: DS-TT Ethernet port MAC address
  // TODO: UE-DS-TT residence time
  // TODO: Port management information container
  // TODO: Ethernet header compression configuration
  // TODO: Suggested interface identifier

  oai::logger::logger_common::nas().debug(
      "Encoded PduSessionEstablishmentRequest message len (%d)", encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int PduSessionEstablishmentRequest::Decode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Decoding PduSessionEstablishmentRequest message");
  int decoded_size    = 0;
  int decoded_ie_size = 0;

  // Header
  decoded_ie_size = Nas5gsmMessage::Decode(buf, len);
  if (decoded_ie_size == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Decoding NAS Header error");
    return KEncodeDecodeError;
  }
  decoded_size += decoded_ie_size;

  if ((decoded_ie_size = NasHelper::Decode(
           ie_integrity_protection_maximum_data_rate_, buf, len, decoded_size,
           false)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // Decode other IEs
  uint8_t octet = 0x00;
  DECODE_U8_VALUE(buf, octet, decoded_size, len);
  oai::logger::logger_common::nas().debug("First option IEI (0x%x)", octet);
  bool flag = false;
  while ((octet != 0x0)) {
    switch ((octet & 0xf0) >> 4) {
      case kIeiPduSessionType: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiPduSessionType);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_pdu_session_type_, buf, len, decoded_size, true)) ==
            KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

      case kIeiSscMode: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiSscMode);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_ssc_mode_, buf, len, decoded_size, true)) ==
            KEncodeDecodeError) {
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

      case kIeiSmPduDnRequestContainer: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiSmPduDnRequestContainer);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_pdu_dn_request_container_, kIeiRejectedNssaiRa, buf, len,
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

      case kIeiIpHeaderCompressionConfiguration: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiIpHeaderCompressionConfiguration);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_ip_header_compression_configuration_, buf, len,
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
      "Decoded PduSessionEstablishmentRequest message len (%d)", decoded_size);
  return decoded_size;
}
