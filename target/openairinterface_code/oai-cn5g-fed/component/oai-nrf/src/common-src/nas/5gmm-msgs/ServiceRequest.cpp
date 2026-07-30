/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "ServiceRequest.hpp"

#include "NasHelper.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
ServiceRequest::ServiceRequest()
    : ie_header_(
          k5gsMobilityManagementMessages, kPlain5gsMessage, kServiceRequest) {
  ie_uplink_data_status_         = std::nullopt;
  ie_pdu_session_status_         = std::nullopt;
  ie_allowed_pdu_session_status_ = std::nullopt;
  ie_nas_message_container_      = std::nullopt;
}

//------------------------------------------------------------------------------
ServiceRequest::~ServiceRequest() {}

//------------------------------------------------------------------------------
uint32_t ServiceRequest::GetLength() const {
  uint32_t msg_len = 0;
  msg_len += ie_header_.GetLength();
  // msg_len += ie_ng_ksi_.GetIeLength();
  // msg_len += ie_service_type_.GetIeLength();
  msg_len += 1;  // 1/2 octet for ngKSI + 1/2 octet for Service type
  msg_len += ie_5g_s_tmsi_.GetIeLength();

  if (ie_uplink_data_status_.has_value())
    msg_len += ie_uplink_data_status_.value().GetIeLength();
  if (ie_pdu_session_status_.has_value())
    msg_len += ie_pdu_session_status_.value().GetIeLength();
  if (ie_allowed_pdu_session_status_.has_value())
    msg_len += ie_allowed_pdu_session_status_.value().GetIeLength();
  if (ie_nas_message_container_.has_value())
    msg_len += ie_nas_message_container_.value().GetIeLength();

  return msg_len;
}

//------------------------------------------------------------------------------
void ServiceRequest::SetHeader(uint8_t security_header_type) {
  ie_header_.SetSecurityHeaderType(security_header_type);
}

//------------------------------------------------------------------------------
void ServiceRequest::SetNgKsi(uint8_t tsc, uint8_t key_set_id) {
  ie_ng_ksi_.Set(false);  // 4 lower bits
  ie_ng_ksi_.SetNasKeyIdentifier(key_set_id);
  ie_ng_ksi_.SetTypeOfSecurityContext(tsc);
}

//------------------------------------------------------------------------------
void ServiceRequest::GetNgKsi(uint8_t& ng_ksi) const {
  ng_ksi = ie_ng_ksi_.GetNgKsi();
}

//------------------------------------------------------------------------------
void ServiceRequest::SetServiceType(uint8_t value) {
  ie_service_type_.Set(true, value);  // 4 higher bit
}

//------------------------------------------------------------------------------
void ServiceRequest::GetServiceType(uint8_t& value) const {
  ie_service_type_.GetValue(value);
}

//------------------------------------------------------------------------------
void ServiceRequest::Set5gSTmsi(
    uint16_t amf_set_id, uint8_t amf_pointer, const std::string& tmsi) {
  ie_5g_s_tmsi_.Set5gSTmsi(amf_set_id, amf_pointer, tmsi);
}

//------------------------------------------------------------------------------
bool ServiceRequest::Get5gSTmsi(
    uint16_t& amf_set_id, uint8_t& amf_pointer, std::string& tmsi) const {
  return ie_5g_s_tmsi_.Get5gSTmsi(amf_set_id, amf_pointer, tmsi);
}

//------------------------------------------------------------------------------
void ServiceRequest::SetUplinkDataStatus(uint16_t value) {
  ie_uplink_data_status_ = std::make_optional<UplinkDataStatus>(value);
}

//------------------------------------------------------------------------------
bool ServiceRequest::GetUplinkDataStatus(uint16_t& value) const {
  if (ie_uplink_data_status_.has_value()) {
    value = ie_uplink_data_status_.value().GetValue();
    return true;
  } else {
    return false;
  }
}

//------------------------------------------------------------------------------
std::optional<uint16_t> ServiceRequest::GetUplinkDataStatus() const {
  if (ie_uplink_data_status_.has_value()) {
    return std::optional<uint16_t>(ie_uplink_data_status_.value().GetValue());
  }
  return std::nullopt;
}
//------------------------------------------------------------------------------
void ServiceRequest::SetPduSessionStatus(uint16_t value) {
  ie_pdu_session_status_ = std::make_optional<PduSessionStatus>(value);
}

//------------------------------------------------------------------------------
bool ServiceRequest::GetPduSessionStatus(uint16_t& value) const {
  if (ie_pdu_session_status_.has_value()) {
    value = ie_pdu_session_status_.value().GetValue();
    return true;
  } else {
    return false;
  }
}

//------------------------------------------------------------------------------
std::optional<uint16_t> ServiceRequest::GetPduSessionStatus() const {
  if (ie_pdu_session_status_.has_value()) {
    return std::optional<uint16_t>(ie_pdu_session_status_.value().GetValue());
  }
  return std::nullopt;
}

//------------------------------------------------------------------------------
void ServiceRequest::SetAllowedPduSessionStatus(uint16_t value) {
  ie_allowed_pdu_session_status_ =
      std::make_optional<AllowedPduSessionStatus>(value);
}

//------------------------------------------------------------------------------
bool ServiceRequest::GetAllowedPduSessionStatus(uint16_t& value) const {
  if (ie_allowed_pdu_session_status_.has_value()) {
    value = ie_allowed_pdu_session_status_.value().GetValue();
    return true;
  } else {
    return false;
  }
}

//------------------------------------------------------------------------------
std::optional<uint16_t> ServiceRequest::GetAllowedPduSessionStatus() const {
  if (ie_allowed_pdu_session_status_.has_value()) {
    return std::optional<uint16_t>(
        ie_allowed_pdu_session_status_.value().GetValue());
  }
  return std::nullopt;
}

//------------------------------------------------------------------------------
void ServiceRequest::SetNasMessageContainer(const bstring& value) {
  ie_nas_message_container_ = std::make_optional<NasMessageContainer>(value);
}

//------------------------------------------------------------------------------
bool ServiceRequest::GetNasMessageContainer(bstring& nas) const {
  if (ie_nas_message_container_.has_value()) {
    ie_nas_message_container_.value().GetValue(nas);
    return true;
  } else {
    return false;
  }
}

//------------------------------------------------------------------------------
int ServiceRequest::Encode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug("Encoding ServiceRequest message...");

  int encoded_size    = 0;
  int encoded_ie_size = 0;

  // Header
  if ((encoded_ie_size = ie_header_.Encode(buf, len)) == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Encoding NAS Header error");
    return KEncodeDecodeError;
  }
  encoded_size += encoded_ie_size;

  // ngKSI and Service Type
  encoded_ie_size = NasHelper::Encode(ie_ng_ksi_, buf, len, encoded_size);
  if ((encoded_ie_size == KEncodeDecodeError) or
      (encoded_ie_size != 0)) {  // 1/2 octet
    return KEncodeDecodeError;
  }
  encoded_ie_size = NasHelper::Encode(ie_service_type_, buf, len, encoded_size);
  if ((encoded_ie_size == KEncodeDecodeError) or
      (encoded_ie_size != 0)) {  // 1/2 octet
    return KEncodeDecodeError;
  }
  encoded_size++;  // 1/2 octet for ngKSI, 1/2 for Service Type

  // 5G-S-TMSI
  if ((encoded_ie_size = NasHelper::Encode(
           ie_5g_s_tmsi_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // Uplink data status
  if ((encoded_ie_size =
           NasHelper::Encode(ie_uplink_data_status_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // PDU session status
  if ((encoded_ie_size =
           NasHelper::Encode(ie_pdu_session_status_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // Allowed PDU session status
  if ((encoded_ie_size = NasHelper::Encode(
           ie_allowed_pdu_session_status_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // NAS message container
  if ((encoded_ie_size = NasHelper::Encode(
           ie_nas_message_container_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  oai::logger::logger_common::nas().debug(
      "Encoded ServiceRequest message (%d)", encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int ServiceRequest::Decode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug("Decoding ServiceRequest message");

  int decoded_size    = 0;
  int decoded_ie_size = 0;

  // Header
  decoded_ie_size = ie_header_.Decode(buf, len);
  if (decoded_ie_size == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Decoding NAS Header error");
    return KEncodeDecodeError;
  }
  decoded_size += decoded_ie_size;

  // ngKSI + Service type
  decoded_ie_size =
      NasHelper::Decode(ie_ng_ksi_, buf, len, decoded_size, false, false);
  if ((decoded_ie_size == KEncodeDecodeError) or (decoded_ie_size != 0)) {
    return KEncodeDecodeError;
  }
  decoded_ie_size =
      NasHelper::Decode(ie_service_type_, buf, len, decoded_size, true, false);
  if ((decoded_ie_size == KEncodeDecodeError) or (decoded_ie_size != 0)) {
    return KEncodeDecodeError;
  }
  decoded_size++;  // 1/2 octet for ngKSI, 1/2 for Service Type

  // 5G-S-TMSI
  if ((decoded_ie_size =
           NasHelper::Decode(ie_5g_s_tmsi_, buf, len, decoded_size, false)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // Decode other IEs
  uint8_t octet = 0x00;
  DECODE_U8_VALUE(buf, octet, decoded_size, len);
  oai::logger::logger_common::nas().debug("First optional IE (0x%x)", octet);
  while ((octet != 0x0)) {
    oai::logger::logger_common::nas().debug("IEI 0x%x", octet);
    switch (octet) {
      case kIeiUplinkDataStatus: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiUplinkDataStatus);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_uplink_data_status_, buf, len, decoded_size, true)) ==
            KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

      case kIeiPduSessionStatus: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiPduSessionStatus);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_pdu_session_status_, buf, len, decoded_size, true)) ==
            KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

      case kIeiAllowedPduSessionStatus: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiAllowedPduSessionStatus);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_allowed_pdu_session_status_, buf, len, decoded_size,
                 true)) == KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

      case kIeiNasMessageContainer: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiNasMessageContainer);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_nas_message_container_, buf, len, decoded_size, true)) ==
            KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

      default: {
        oai::logger::logger_common::nas().warn(
            "Unknown IEI 0x%x, stop decoding...", octet);
        // Stop decoding
        octet = 0x00;
      }
    }
  }

  oai::logger::logger_common::nas().debug(
      "Decoded ServiceRequest message len (%d)", decoded_size);
  return decoded_size;
}
