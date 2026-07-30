/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "RegistrationReject.hpp"

#include "NasHelper.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
RegistrationReject::RegistrationReject()
    : ie_header_(
          k5gsMobilityManagementMessages, kPlain5gsMessage,
          kRegistrationReject) {
  oai::logger::logger_common::nas().debug("Initiating RegistrationReject");
  ie_t3346_value_    = std::nullopt;
  ie_t3502_value_    = std::nullopt;
  ie_eap_message_    = std::nullopt;
  ie_rejected_nssai_ = std::nullopt;
}

//------------------------------------------------------------------------------
RegistrationReject::~RegistrationReject() {
  ie_t3346_value_    = std::nullopt;
  ie_t3502_value_    = std::nullopt;
  ie_eap_message_    = std::nullopt;
  ie_rejected_nssai_ = std::nullopt;
}

//------------------------------------------------------------------------------
uint32_t RegistrationReject::GetLength() const {
  uint32_t msg_len = 0;
  msg_len += ie_header_.GetLength();
  msg_len += ie_5gmm_cause_.GetIeLength();
  if (ie_t3346_value_.has_value())
    msg_len += ie_t3346_value_.value().GetIeLength();
  if (ie_t3502_value_.has_value())
    msg_len += ie_t3502_value_.value().GetIeLength();
  if (ie_eap_message_.has_value())
    msg_len += ie_eap_message_.value().GetIeLength();
  if (ie_rejected_nssai_.has_value())
    msg_len += ie_rejected_nssai_.value().GetIeLength();

  return msg_len;
}

//------------------------------------------------------------------------------
void RegistrationReject::SetHeader(uint8_t security_header_type) {
  ie_header_.SetSecurityHeaderType(security_header_type);
}

//------------------------------------------------------------------------------
void RegistrationReject::Set5gmmCause(uint8_t value) {
  ie_5gmm_cause_.SetValue(value);
}

//------------------------------------------------------------------------------
void RegistrationReject::SetT3346(uint8_t value) {
  ie_t3346_value_ = std::make_optional<GprsTimer2>(kT3346Value, value);
}

//------------------------------------------------------------------------------
void RegistrationReject::SetT3502(uint8_t value) {
  ie_t3502_value_ = std::make_optional<GprsTimer2>(kT3502Value, value);
}

//------------------------------------------------------------------------------
void RegistrationReject::SetEapMessage(const bstring& eap) {
  ie_eap_message_ = std::make_optional<EapMessage>(kIeiEapMessage, eap);
}

//------------------------------------------------------------------------------
void RegistrationReject::SetRejectedNssai(
    const std::vector<RejectedSNssai>& nssai) {
  ie_rejected_nssai_ = std::make_optional<RejectedNssai>(kIeiRejectedNssaiRr);
  ie_rejected_nssai_.value().SetRejectedSNssais(nssai);
}

//------------------------------------------------------------------------------
int RegistrationReject::Encode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Encoding RegistrationReject message");
  int encoded_size    = 0;
  int encoded_ie_size = 0;
  // Header
  if ((encoded_ie_size = ie_header_.Encode(buf, len)) == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Encoding NAS Header error");
    return KEncodeDecodeError;
  }
  encoded_size += encoded_ie_size;

  // 5GMM Cause
  if ((encoded_ie_size = NasHelper::Encode(
           ie_5gmm_cause_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // Timer 3346
  if ((encoded_ie_size = NasHelper::Encode(
           ie_t3346_value_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // Timer T3502
  if ((encoded_ie_size = NasHelper::Encode(
           ie_t3502_value_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // EAP Message
  if ((encoded_ie_size = NasHelper::Encode(
           ie_eap_message_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // Rejected NSSAI
  if ((encoded_ie_size = NasHelper::Encode(
           ie_rejected_nssai_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  oai::logger::logger_common::nas().debug(
      "Encoded RegistrationReject message len (%d)", encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int RegistrationReject::Decode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Decoding RegistrationReject message");
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

  // Decode other IEs
  uint8_t octet = 0x00;
  DECODE_U8_VALUE(buf, octet, decoded_size, len);
  oai::logger::logger_common::nas().debug("First option IEI (0x%x)", octet);
  while ((octet != 0x0)) {
    oai::logger::logger_common::nas().debug("IEI 0x%x", octet);
    switch (octet) {
      case kT3346Value: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kT3346Value);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_t3346_value_, kT3346Value, buf, len, decoded_size, true)) ==
            KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

      case kT3502Value: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kT3502Value);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_t3502_value_, kT3502Value, buf, len, decoded_size, true)) ==
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

      case kIeiRejectedNssaiRr: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiRejectedNssaiRr);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_rejected_nssai_, kIeiRejectedNssaiRr, buf, len,
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
      "Decoded RegistrationReject message len(%d)", decoded_size);
  return decoded_size;
}
