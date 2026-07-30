/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "UlNasTransport.hpp"

#include "NasHelper.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
UlNasTransport::UlNasTransport()
    : ie_header_(
          k5gsMobilityManagementMessages, kPlain5gsMessage, kUlNasTransport) {
  ie_pdu_session_id_                = std::nullopt;
  ie_old_pdu_session_id_            = std::nullopt;
  ie_request_type_                  = std::nullopt;
  ie_s_nssai_                       = std::nullopt;
  ie_dnn_                           = std::nullopt;
  ie_additional_information_        = std::nullopt;
  ie_ma_pdu_session_information_    = std::nullopt;
  ie_release_assistance_indication_ = std::nullopt;
}

//------------------------------------------------------------------------------
UlNasTransport::~UlNasTransport() {}

//------------------------------------------------------------------------------
uint32_t UlNasTransport::GetLength() const {
  uint32_t msg_len = 0;
  msg_len += ie_header_.GetLength();
  // msg_len += ie_payload_container_type_.GetIeLength();
  msg_len += 1;  // 1/2 for Payload container type + 1/2 for Spare half octet
  msg_len += ie_payload_container_.GetIeLength();

  if (ie_pdu_session_id_.has_value())
    msg_len += ie_pdu_session_id_.value().GetIeLength();
  if (ie_old_pdu_session_id_.has_value())
    msg_len += ie_old_pdu_session_id_.value().GetIeLength();
  if (ie_request_type_.has_value())
    msg_len += ie_request_type_.value().GetIeLength();
  if (ie_s_nssai_.has_value()) msg_len += ie_s_nssai_.value().GetIeLength();
  if (ie_dnn_.has_value()) msg_len += ie_dnn_.value().GetIeLength();
  if (ie_additional_information_.has_value())
    msg_len += ie_additional_information_.value().GetIeLength();
  if (ie_ma_pdu_session_information_.has_value())
    msg_len += ie_ma_pdu_session_information_.value().GetIeLength();
  if (ie_release_assistance_indication_.has_value())
    msg_len += ie_release_assistance_indication_.value().GetIeLength();

  return msg_len;
}

//------------------------------------------------------------------------------
void UlNasTransport::SetHeader(uint8_t security_header_type) {
  ie_header_.SetSecurityHeaderType(security_header_type);
}

//------------------------------------------------------------------------------
void UlNasTransport::SetPayloadContainerType(uint8_t value) {
  ie_payload_container_type_.SetValue(value);
}

//------------------------------------------------------------------------------
uint8_t UlNasTransport::GetPayloadContainerType() const {
  return ie_payload_container_type_.GetValue();
}

//------------------------------------------------------------------------------
void UlNasTransport::SetPayloadContainer(
    const std::vector<PayloadContainerEntry>& content) {
  ie_payload_container_.SetValue(content);
}

//------------------------------------------------------------------------------
void UlNasTransport::GetPayloadContainer(bstring& content) const {
  ie_payload_container_.GetValue(content);
}

//------------------------------------------------------------------------------
void UlNasTransport::GetPayloadContainer(
    std::vector<PayloadContainerEntry>& content) const {
  ie_payload_container_.GetValue(content);
}

//------------------------------------------------------------------------------
void UlNasTransport::SetPduSessionId(uint8_t value) {
  ie_pdu_session_id_ =
      std::make_optional<PduSessionIdentity2>(kIeiPduSessionId, value);
}

//------------------------------------------------------------------------------
bool UlNasTransport::GetPduSessionId(uint8_t& value) const {
  if (ie_pdu_session_id_.has_value()) {
    value = ie_pdu_session_id_.value().GetValue();
    return true;
  } else {
    return false;
  }
}

//------------------------------------------------------------------------------
void UlNasTransport::SetOldPduSessionId(uint8_t value) {
  ie_old_pdu_session_id_ =
      std::make_optional<PduSessionIdentity2>(kIeiOldPduSessionId, value);
}

//------------------------------------------------------------------------------
bool UlNasTransport::GetOldPduSessionId(uint8_t& value) const {
  if (ie_old_pdu_session_id_.has_value()) {
    value = ie_old_pdu_session_id_.value().GetValue();
    return true;
  } else {
    return false;
  }
}

//------------------------------------------------------------------------------
void UlNasTransport::SetRequestType(uint8_t value) {
  ie_request_type_ = std::make_optional<RequestType>(value);
}

//------------------------------------------------------------------------------
bool UlNasTransport::GetRequestType(uint8_t& value) const {
  if (ie_request_type_.has_value()) {
    value = ie_request_type_.value().GetValue();
    return true;
  } else {
    return false;
  }
}

//------------------------------------------------------------------------------
void UlNasTransport::SetSNssai(const SNSSAI_s& snssai) {
  ie_s_nssai_ =
      std::make_optional<SNssai>(std::optional<uint8_t>{kIeiSNssai}, snssai);
}

//------------------------------------------------------------------------------
bool UlNasTransport::GetSNssai(SNSSAI_s& snssai) const {
  if (ie_s_nssai_.has_value()) {
    ie_s_nssai_.value().GetValue(snssai);
    return true;
  } else {
    return false;
  }
}

//------------------------------------------------------------------------------
void UlNasTransport::SetDnn(const bstring& dnn) {
  ie_dnn_ = std::make_optional<Dnn>(dnn);
}

//------------------------------------------------------------------------------
bool UlNasTransport::GetDnn(bstring& dnn) const {
  if (ie_dnn_.has_value()) {
    ie_dnn_.value().GetValue(dnn);
    return true;
  } else {
    return false;
  }
}

//------------------------------------------------------------------------------
void UlNasTransport::SetAdditionalInformation(const bstring& value) {
  ie_additional_information_ = std::make_optional<AdditionalInformation>(value);
}

//------------------------------------------------------------------------------
void UlNasTransport::SetMaPduSessionInformation(uint8_t value) {
  ie_ma_pdu_session_information_ =
      std::make_optional<MaPduSessionInformation>(value);
}

//------------------------------------------------------------------------------
void UlNasTransport::SetReleaseAssistanceIndication(uint8_t value) {
  ie_release_assistance_indication_ =
      std::make_optional<ReleaseAssistanceIndication>(value);
}

//------------------------------------------------------------------------------
int UlNasTransport::Encode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug("Encoding UL NAS Transport message");
  int encoded_size    = 0;
  int encoded_ie_size = 0;

  // Header
  if ((encoded_ie_size = ie_header_.Encode(buf, len)) == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Encoding NAS Header error");
    return KEncodeDecodeError;
  }
  encoded_size += encoded_ie_size;

  // Payload Container Type
  if ((encoded_ie_size = NasHelper::Encode(
           ie_payload_container_type_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }
  if (encoded_ie_size == 0)
    encoded_size++;  // 1/2 octet for  ie_payload_container_type_, 1/2 octet for
                     // spare

  // Payload container
  // TODO: use NAS helper
  encoded_ie_size = ie_payload_container_.Encode(
      buf + encoded_size, len - encoded_size,
      ie_payload_container_type_.GetValue());
  if (encoded_ie_size != KEncodeDecodeError) {
    encoded_size += encoded_ie_size;
  } else {
    oai::logger::logger_common::nas().error(
        "Decoding %s error", PayloadContainer::GetIeName().c_str());
    return KEncodeDecodeError;
  }

  // PDU session ID
  if ((encoded_ie_size = NasHelper::Encode(
           ie_pdu_session_id_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // Old PDU session ID
  if ((encoded_ie_size =
           NasHelper::Encode(ie_old_pdu_session_id_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // Request type
  if ((encoded_ie_size = NasHelper::Encode(
           ie_request_type_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // S-NSSAI
  if ((encoded_ie_size = NasHelper::Encode(
           ie_s_nssai_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // DNN
  if ((encoded_ie_size = NasHelper::Encode(ie_dnn_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // Additional information
  if ((encoded_ie_size = NasHelper::Encode(
           ie_additional_information_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // MA PDU session information
  if ((encoded_ie_size = NasHelper::Encode(
           ie_ma_pdu_session_information_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // Release assistance indication
  if ((encoded_ie_size = NasHelper::Encode(
           ie_release_assistance_indication_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  oai::logger::logger_common::nas().debug(
      "Encoded UL NAS Transport message len (%d)", encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int UlNasTransport::Decode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug("Decoding UlNasTransport message");
  int decoded_size    = 0;
  int decoded_ie_size = 0;

  // Header
  decoded_ie_size = ie_header_.Decode(buf, len);
  if (decoded_ie_size == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Decoding NAS Header error");
    return KEncodeDecodeError;
  }
  decoded_size += decoded_ie_size;

  // Payload Container Type
  if ((decoded_ie_size = NasHelper::Decode(
           ie_payload_container_type_, buf, len, decoded_size, false)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }
  if (decoded_ie_size == 0)
    decoded_size++;  // 1/2 octet for PayloadContainerType, 1/2 octet for spare

  // Payload Container
  // TODO: use NAS helper
  decoded_ie_size = ie_payload_container_.Decode(
      buf + decoded_size, len - decoded_size, false,
      ie_payload_container_type_.GetValue());
  if (decoded_ie_size == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error(
        "Decoding %s error", PayloadContainer::GetIeName().c_str());
    return KEncodeDecodeError;
  }
  decoded_size += decoded_ie_size;

  oai::logger::logger_common::nas().debug("Decoded_size (%d)", decoded_size);

  // Decode other IEs
  uint8_t octet = 0x00;
  DECODE_U8_VALUE(buf, octet, decoded_size, len);
  oai::logger::logger_common::nas().debug("First option IEI (0x%x)", octet);
  bool flag = false;

  while ((octet != 0x0)) {
    switch ((octet & 0xf0) >> 4) {
      case kIeiRequestType: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiRequestType);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_request_type_, buf, len, decoded_size, true)) ==
            KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

      case kIeiMaPduSessionInformation: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiMaPduSessionInformation);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_ma_pdu_session_information_, buf, len, decoded_size,
                 true)) == KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

      case kIeiReleaseAssistanceIndication: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiReleaseAssistanceIndication);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_release_assistance_indication_, buf, len, decoded_size,
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
      case kIeiPduSessionId: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiPduSessionId);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_pdu_session_id_, buf, len, decoded_size, true)) ==
            KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

      case kIeiOldPduSessionId: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiOldPduSessionId);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_old_pdu_session_id_, buf, len, decoded_size, true)) ==
            KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

      case kIeiSNssai: {
        oai::logger::logger_common::nas().debug("Decoding IEI (0x22)");
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_s_nssai_, kIeiSNssai, buf, len, decoded_size,
                 kIeIsOptional)) == KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

      case kIeiDnn: {
        oai::logger::logger_common::nas().debug("Decoding IEI (0x25)");
        if ((decoded_ie_size =
                 NasHelper::Decode(ie_dnn_, buf, len, decoded_size, true)) ==
            KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

      case kIeiAdditionalInformation: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiAdditionalInformation);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_additional_information_, buf, len, decoded_size, true)) ==
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
    flag = false;
  }

  oai::logger::logger_common::nas().debug(
      "Decoded UlNasTransport message len (%d)", decoded_size);
  return decoded_size;
}
