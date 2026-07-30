/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "DlNasTransport.hpp"

#include "NasHelper.hpp"
#include "bstrlib.h"

using namespace oai::nas;

//------------------------------------------------------------------------------
DlNasTransport::DlNasTransport()
    : ie_header_(
          k5gsMobilityManagementMessages, kPlain5gsMessage, kDlNasTransport) {
  ie_pdu_session_identity_2_ = std::nullopt;
  ie_additional_information_ = std::nullopt;
  ie_5gmm_cause_             = std::nullopt;
  ie_back_off_timer_value_   = std::nullopt;
}

//------------------------------------------------------------------------------
DlNasTransport::~DlNasTransport() {}

//------------------------------------------------------------------------------
uint32_t DlNasTransport::GetLength() const {
  uint32_t msg_len = 0;
  msg_len += ie_header_.GetLength();
  // msg_len += ie_payload_container_type_.GetIeLength();
  msg_len += 1;  // 1/2 for Payload container type + 1/2 for Spare half octet
  msg_len += ie_payload_container_.GetIeLength();
  if (ie_pdu_session_identity_2_.has_value())
    msg_len += ie_pdu_session_identity_2_.value().GetIeLength();
  if (ie_additional_information_.has_value())
    msg_len += ie_additional_information_.value().GetIeLength();
  if (ie_5gmm_cause_.has_value())
    msg_len += ie_5gmm_cause_.value().GetIeLength();
  if (ie_back_off_timer_value_.has_value())
    msg_len += ie_back_off_timer_value_.value().GetIeLength();

  return msg_len;
}

//------------------------------------------------------------------------------
void DlNasTransport::SetHeader(uint8_t security_header_type) {
  ie_header_.SetSecurityHeaderType(security_header_type);
}

//------------------------------------------------------------------------------
void DlNasTransport::SetPayloadContainerType(uint8_t value) {
  ie_payload_container_type_.SetValue(value);
}

//------------------------------------------------------------------------------
void DlNasTransport::SetPayloadContainer(
    const std::vector<PayloadContainerEntry>& content) {
  ie_payload_container_.SetValue(content);
}

//------------------------------------------------------------------------------
void DlNasTransport::SetPayloadContainer(uint8_t* buf, int len) {
  bstring b = blk2bstr(buf, len);
  ie_payload_container_.SetValue(b);
}

//------------------------------------------------------------------------------
void DlNasTransport::SetPduSessionId(uint8_t value) {
  ie_pdu_session_identity_2_ =
      std::make_optional<PduSessionIdentity2>(kIeiPduSessionId, value);
}

//------------------------------------------------------------------------------
void DlNasTransport::SetAdditionalInformation(const bstring& value) {
  ie_additional_information_ = std::make_optional<AdditionalInformation>(value);
}

//------------------------------------------------------------------------------
void DlNasTransport::Set5gmmCause(uint8_t value) {
  ie_5gmm_cause_ = std::make_optional<_5gmmCause>(kIei5gmmCause, value);
}

//------------------------------------------------------------------------------
void DlNasTransport::SetBackOffTimerValue(uint8_t unit, uint8_t value) {
  ie_back_off_timer_value_ =
      std::make_optional<GprsTimer3>(kIeiGprsTimer3BackOffTimer, unit, value);
}

//------------------------------------------------------------------------------
int DlNasTransport::Encode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug("Encoding DlNasTransport message");

  int encoded_size    = 0;
  int encoded_ie_size = 0;

  // Header
  if ((encoded_ie_size = ie_header_.Encode(buf, len)) == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Encoding NAS Header error");
    return KEncodeDecodeError;
  }
  encoded_size += encoded_ie_size;

  // Payload container type
  if ((encoded_ie_size = NasHelper::Encode(
           ie_payload_container_type_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }
  if (encoded_ie_size == 0)
    // Spare half octet
    encoded_size++;  // 1/2 octet + 1/2 octet for Payload container type

  // Payload container
  encoded_ie_size = ie_payload_container_.Encode(
      buf + encoded_size, len - encoded_size,
      ie_payload_container_type_.GetValue());
  if (encoded_ie_size != KEncodeDecodeError) {
    encoded_size += encoded_ie_size;
  } else {
    oai::logger::logger_common::nas().error(
        "Encoding %s error", PayloadContainer::GetIeName().c_str());
    return KEncodeDecodeError;
  }
  /*
    if ((encoded_ie_size = NasHelper::Encode(
                    ie_payload_container_, buf, len, encoded_size)) ==
        KEncodeDecodeError) {
      return KEncodeDecodeError;
    }
  */

  // PDU session ID
  if ((encoded_ie_size = NasHelper::Encode(
           ie_pdu_session_identity_2_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // Additional information
  if ((encoded_ie_size = NasHelper::Encode(
           ie_additional_information_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // 5GMM cause
  if ((encoded_ie_size = NasHelper::Encode(
           ie_5gmm_cause_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // Back-off timer value
  if ((encoded_ie_size = NasHelper::Encode(
           ie_back_off_timer_value_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  oai::logger::logger_common::nas().debug(
      "Encoded DlNasTransport message len (%d)", encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int DlNasTransport::Decode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug("Decoding DlNasTransport message");

  int decoded_size    = 0;
  int decoded_ie_size = 0;

  // Header
  decoded_ie_size = ie_header_.Decode(buf, len);
  if (decoded_ie_size == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Decoding NAS Header error");
    return KEncodeDecodeError;
  }
  decoded_size += decoded_ie_size;

  // Payload container type
  if ((decoded_ie_size = NasHelper::Decode(
           ie_payload_container_type_, buf, len, decoded_size, false)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }
  if (decoded_ie_size == 0)
    decoded_size++;  // 1/2 octet for PayloadContainerType, 1/2 octet for spare

  // Payload container
  decoded_ie_size = ie_payload_container_.Decode(
      buf + decoded_size, len - decoded_size, false,
      kN1SmInformation);  // TODO: verified Type of Payload Container
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
  while ((octet != 0x0)) {
    oai::logger::logger_common::nas().debug("Decoding IEI 0x%x", octet);
    switch (octet) {
      case kIeiPduSessionId: {
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_pdu_session_identity_2_, buf, len, decoded_size, true)) ==
            KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

      case kIeiAdditionalInformation: {
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_additional_information_, buf, len, decoded_size, true)) ==
            KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

      case kIei5gmmCause: {
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_5gmm_cause_, buf, len, decoded_size, true)) ==
            KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

      case kIeiGprsTimer3BackOffTimer: {
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_5gmm_cause_, kIeiGprsTimer3BackOffTimer, buf, len,
                 decoded_size, true)) == KEncodeDecodeError) {
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
      } break;
    }
  }

  oai::logger::logger_common::nas().debug(
      "Decoded DlNasTransport message len (%d)", decoded_size);
  return decoded_size;
}
