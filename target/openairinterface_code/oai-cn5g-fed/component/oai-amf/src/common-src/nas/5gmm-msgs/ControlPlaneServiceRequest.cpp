/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "ControlPlaneServiceRequest.hpp"

#include "NasHelper.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
ControlPlaneServiceRequest::ControlPlaneServiceRequest()
    : ie_header_(
          k5gsMobilityManagementMessages, kPlain5gsMessage, kServiceRequest) {
  ie_pdu_session_status_    = std::nullopt;
  ie_uplink_data_status_    = std::nullopt;
  ie_nas_message_container_ = std::nullopt;
}

//------------------------------------------------------------------------------
ControlPlaneServiceRequest::~ControlPlaneServiceRequest() {}

//------------------------------------------------------------------------------
uint32_t ControlPlaneServiceRequest::GetLength() const {
  uint32_t msg_len = 0;
  msg_len += ie_header_.GetLength();
  // msg_len += ie_control_plane_service_type_.GetIeLength();
  // msg_len += ie_ng_ksi_.GetIeLength();
  msg_len += 1;  // 1/2 for Control plane service type + 1/2 for ngKSI
  if (ie_pdu_session_status_.has_value())
    msg_len += ie_pdu_session_status_.value().GetIeLength();
  if (ie_uplink_data_status_.has_value())
    msg_len += ie_uplink_data_status_.value().GetIeLength();
  if (ie_nas_message_container_.has_value())
    msg_len += ie_nas_message_container_.value().GetIeLength();

  return msg_len;
}

//------------------------------------------------------------------------------
void ControlPlaneServiceRequest::SetHeader(uint8_t security_header_type) {
  ie_header_.SetSecurityHeaderType(security_header_type);
}

//------------------------------------------------------------------------------
void ControlPlaneServiceRequest::SetControlPlaneServiceType(uint8_t value) {
  ie_control_plane_service_type_.Set(false, value);  // 4 lower bit
}

//------------------------------------------------------------------------------
void ControlPlaneServiceRequest::GetControlPlaneServiceType(
    uint8_t& value) const {
  ie_control_plane_service_type_.GetValue(value);
}

//------------------------------------------------------------------------------
void ControlPlaneServiceRequest::SetNgKsi(uint8_t tsc, uint8_t key_set_id) {
  ie_ng_ksi_.Set(true);  // 4 higher bits
  ie_ng_ksi_.SetNasKeyIdentifier(key_set_id);
  ie_ng_ksi_.SetTypeOfSecurityContext(tsc);
}

//------------------------------------------------------------------------------
void ControlPlaneServiceRequest::GetNgKsi(uint8_t& ng_ksi) const {
  ng_ksi = ie_ng_ksi_.GetNgKsi();
}

//------------------------------------------------------------------------------
void ControlPlaneServiceRequest::SetPduSessionStatus(uint16_t value) {
  ie_pdu_session_status_ = std::make_optional<PduSessionStatus>(value);
}

//------------------------------------------------------------------------------
bool ControlPlaneServiceRequest::GetPduSessionStatus(uint16_t& value) const {
  if (ie_pdu_session_status_.has_value()) {
    value = ie_pdu_session_status_.value().GetValue();
    return true;
  } else {
    return false;
  }
}

//------------------------------------------------------------------------------
std::optional<uint16_t> ControlPlaneServiceRequest::GetPduSessionStatus()
    const {
  if (ie_pdu_session_status_.has_value()) {
    return std::optional<uint16_t>(ie_pdu_session_status_.value().GetValue());
  }
  return std::nullopt;
}

//------------------------------------------------------------------------------
void ControlPlaneServiceRequest::SetUplinkDataStatus(uint16_t value) {
  ie_uplink_data_status_ = std::make_optional<UplinkDataStatus>(value);
}

//------------------------------------------------------------------------------
bool ControlPlaneServiceRequest::GetUplinkDataStatus(uint16_t& value) const {
  if (ie_uplink_data_status_.has_value()) {
    value = ie_uplink_data_status_.value().GetValue();
    return true;
  } else {
    return false;
  }
}

//------------------------------------------------------------------------------
void ControlPlaneServiceRequest::SetNasMessageContainer(const bstring& value) {
  ie_nas_message_container_ = std::make_optional<NasMessageContainer>(value);
}

//------------------------------------------------------------------------------
bool ControlPlaneServiceRequest::GetNasMessageContainer(bstring& nas) const {
  if (ie_nas_message_container_.has_value()) {
    ie_nas_message_container_.value().GetValue(nas);
    return true;
  } else {
    return false;
  }
}

//------------------------------------------------------------------------------
int ControlPlaneServiceRequest::Encode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Encoding ControlPlaneServiceRequest message...");

  int encoded_size    = 0;
  int encoded_ie_size = 0;

  // Header
  if ((encoded_ie_size = ie_header_.Encode(buf, len)) == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Encoding NAS Header error");
    return KEncodeDecodeError;
  }
  encoded_size += encoded_ie_size;

  // Control Plane Service Type and ngKSI
  encoded_ie_size =
      NasHelper::Encode(ie_control_plane_service_type_, buf, len, encoded_size);
  if ((encoded_ie_size == KEncodeDecodeError) or
      (encoded_ie_size != 0)) {  // 1/2 octet
    return KEncodeDecodeError;
  }
  encoded_ie_size = NasHelper::Encode(ie_ng_ksi_, buf, len, encoded_size);
  if ((encoded_ie_size == KEncodeDecodeError) or
      (encoded_ie_size != 0)) {  // 1/2 octet
    return KEncodeDecodeError;
  }
  encoded_size++;  // 1/2 for Control Plane Service Type, 1/2 octet for ngKSI

  // TODO: CIoT small data container (Optional)
  // TODO: Payload container type (Optional)
  // TODO: Payload container (Optional)
  // TODO: PDU session ID (Optional)

  // PDU session status
  if ((encoded_ie_size =
           NasHelper::Encode(ie_pdu_session_status_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // TODO: Release assistance indication (Optional)

  // Uplink data status
  if ((encoded_ie_size =
           NasHelper::Encode(ie_uplink_data_status_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // NAS message container
  if ((encoded_ie_size = NasHelper::Encode(
           ie_nas_message_container_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // TODO: Additional information (Optional)

  oai::logger::logger_common::nas().debug(
      "Encoded ControlPlaneServiceRequest message (%d)", encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int ControlPlaneServiceRequest::Decode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Decoding ControlPlaneServiceRequest message");

  int decoded_size    = 0;
  int decoded_ie_size = 0;

  // Header
  decoded_ie_size = ie_header_.Decode(buf, len);
  if (decoded_ie_size == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Decoding NAS Header error");
    return KEncodeDecodeError;
  }
  decoded_size += decoded_ie_size;

  // Control Plane service type + ngKSI
  decoded_ie_size = ie_control_plane_service_type_.Decode(
      buf + decoded_size, len - decoded_size, false, false);
  if ((decoded_ie_size == KEncodeDecodeError) or (decoded_ie_size != 0))
    return KEncodeDecodeError;

  decoded_ie_size =
      ie_ng_ksi_.Decode(buf + decoded_size, len - decoded_size, true, false);
  if ((decoded_ie_size == KEncodeDecodeError) or (decoded_ie_size != 0))
    return KEncodeDecodeError;
  decoded_size++;  // 1/2 for Control Plane Service Type, 1/2 octet for ngKSI

  // Decode other IEs
  uint8_t octet = 0x00;
  DECODE_U8_VALUE(buf, octet, decoded_size, len);
  oai::logger::logger_common::nas().debug("First optional IE (0x%x)", octet);
  while ((octet != 0x0)) {
    oai::logger::logger_common::nas().debug("Decoding IEI 0x%x", octet);
    switch (octet) {
      // TODO: CIoT small data container (Optional)
      // TODO: Payload container type (Optional)
      // TODO: Payload container (Optional)
      // TODO: PDU session ID (Optional)
      case kIeiPduSessionStatus: {
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_pdu_session_status_, buf, len, decoded_size, true)) ==
            KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

        // TODO: Release assistance indication (Optional)

      case kIeiUplinkDataStatus: {
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_uplink_data_status_, buf, len, decoded_size, true)) ==
            KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

      case kIeiNasMessageContainer: {
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_nas_message_container_, buf, len, decoded_size, true)) ==
            KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

        // TODO: Additional information (Optional)

      default: {
        oai::logger::logger_common::nas().warn(
            "Unknown IEI 0x%x, stop decoding...", octet);
        // Stop decoding
        octet = 0x00;
      }
    }
  }

  oai::logger::logger_common::nas().debug(
      "Decoded ControlPlaneServiceRequest message len (%d)", decoded_size);
  return decoded_size;
}
