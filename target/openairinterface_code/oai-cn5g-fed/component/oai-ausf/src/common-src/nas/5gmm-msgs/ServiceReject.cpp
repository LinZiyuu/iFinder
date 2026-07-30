/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "ServiceReject.hpp"

#include "NasHelper.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
ServiceReject::ServiceReject()
    : ie_header_(
          k5gsMobilityManagementMessages, kPlain5gsMessage, kServiceReject) {
  ie_pdu_session_status_ = std::nullopt;
  ie_t3346_value_        = std::nullopt;
  ie_eap_message_        = std::nullopt;
  ie_t3448_value_        = std::nullopt;
}

//------------------------------------------------------------------------------
ServiceReject::~ServiceReject() {}

//------------------------------------------------------------------------------
uint32_t ServiceReject::GetLength() const {
  uint32_t msg_len = 0;
  msg_len += ie_header_.GetLength();
  msg_len += ie_5gmm_cause_.GetIeLength();
  if (ie_pdu_session_status_.has_value())
    msg_len += ie_pdu_session_status_.value().GetIeLength();
  if (ie_t3346_value_.has_value())
    msg_len += ie_t3346_value_.value().GetIeLength();
  if (ie_eap_message_.has_value())
    msg_len += ie_eap_message_.value().GetIeLength();
  if (ie_t3448_value_.has_value())
    msg_len += ie_t3448_value_.value().GetIeLength();

  return msg_len;
}

//------------------------------------------------------------------------------
void ServiceReject::SetHeader(uint8_t security_header_type) {
  ie_header_.SetSecurityHeaderType(security_header_type);
}

//------------------------------------------------------------------------------
void ServiceReject::Set5gmmCause(uint8_t value) {
  ie_5gmm_cause_.SetValue(value);
}

//------------------------------------------------------------------------------
uint8_t ServiceReject::Get5GMmCause() {
  return ie_5gmm_cause_.GetValue();
}

//------------------------------------------------------------------------------
void ServiceReject::SetPduSessionStatus(uint16_t value) {
  ie_pdu_session_status_ = std::make_optional<PduSessionStatus>(value);
}

//------------------------------------------------------------------------------
void ServiceReject::SetT3346Value(uint8_t value) {
  ie_t3346_value_ = std::make_optional<GprsTimer2>(kT3346Value, value);
}

//------------------------------------------------------------------------------
void ServiceReject::SetEapMessage(const bstring& eap) {
  ie_eap_message_ = std::make_optional<EapMessage>(kIeiEapMessage, eap);
}

//------------------------------------------------------------------------------
void ServiceReject::SetT3448Value(uint8_t unit, uint8_t value) {
  ie_t3448_value_ =
      std::make_optional<GprsTimer3>(kIeiGprsTimer3T3448, unit, value);
}

//------------------------------------------------------------------------------
int ServiceReject::Encode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug("Encoding Service Reject message");
  int encoded_size    = 0;
  int encoded_ie_size = 0;
  // Header
  if ((encoded_ie_size = ie_header_.Encode(buf, len)) == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Encoding NAS Header error");
    return KEncodeDecodeError;
  }
  encoded_size += encoded_ie_size;

  // 5GMM cause
  if ((encoded_ie_size = NasHelper::Encode(
           ie_5gmm_cause_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // PDU session status
  if ((encoded_ie_size =
           NasHelper::Encode(ie_pdu_session_status_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // T3346 value
  if ((encoded_ie_size = NasHelper::Encode(
           ie_t3346_value_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // EAP message
  if ((encoded_ie_size = NasHelper::Encode(
           ie_eap_message_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // T3448 value
  if ((encoded_ie_size = NasHelper::Encode(
           ie_t3448_value_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  oai::logger::logger_common::nas().debug(
      "Encoded Service Reject message len (%d)", encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int ServiceReject::Decode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Decoding RegistrationAccept message");
  int decoded_size    = 0;
  int decoded_ie_size = 0;

  // Header
  decoded_ie_size = ie_header_.Decode(buf, len);
  if (decoded_ie_size == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Decoding NAS Header error");
    return KEncodeDecodeError;
  }
  decoded_size += decoded_ie_size;

  // 5GMM Cause
  if ((decoded_ie_size =
           NasHelper::Decode(ie_5gmm_cause_, buf, len, decoded_size, false)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  oai::logger::logger_common::nas().debug("Decoded_size (%d)", decoded_size);

  // Decode other IEs
  uint8_t octet = 0x00;
  DECODE_U8_VALUE(buf, octet, decoded_size, len);
  oai::logger::logger_common::nas().debug("First option IEI (0x%x)", octet);

  while ((octet != 0x0)) {
    oai::logger::logger_common::nas().debug("Decoding IEI 0x%x", octet);
    switch (octet) {
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

      case kT3346Value: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x5F: T3346 Value");
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_t3346_value_, kT3346Value, buf, len, decoded_size, true)) ==
            KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

      case kIeiEapMessage: {
        oai::logger::logger_common::nas().debug("Decoding IEI (0x78)");
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_eap_message_, buf, len, decoded_size, true)) ==
            KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

      case kIeiGprsTimer3T3448: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiGprsTimer3T3448);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_t3448_value_, kIeiGprsTimer3T3448, buf, len, decoded_size,
                 true)) == KEncodeDecodeError) {
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
      "Decoded Service Reject message len (%d)", decoded_size);
  return decoded_size;
}
