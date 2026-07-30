/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "DeregistrationRequestUeTerminated.hpp"

#include "NasHelper.hpp"
#include "conversions.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
DeregistrationRequestUeTerminated::DeregistrationRequestUeTerminated()
    : ie_header_(
          k5gsMobilityManagementMessages, kPlain5gsMessage,
          kDeregistrationRequestUeTerminated) {}

//------------------------------------------------------------------------------
DeregistrationRequestUeTerminated::~DeregistrationRequestUeTerminated() {}

//------------------------------------------------------------------------------
uint32_t DeregistrationRequestUeTerminated::GetLength() const {
  uint32_t msg_len = 0;
  msg_len += ie_header_.GetLength();
  // msg_len += ie_deregistration_type_.GetIeLength();
  msg_len += 1;  // 1/2 for De-registration type + 1/2 for Spare half octet
  if (ie_5gmm_cause_.has_value())
    msg_len += ie_5gmm_cause_.value().GetIeLength();
  if (ie_t3346_value_.has_value())
    msg_len += ie_t3346_value_.value().GetIeLength();
  if (ie_rejected_nssai_.has_value())
    msg_len += ie_rejected_nssai_.value().GetIeLength();

  return msg_len;
}

//------------------------------------------------------------------------------
void DeregistrationRequestUeTerminated::SetHeader(
    uint8_t security_header_type) {
  ie_header_.SetSecurityHeaderType(security_header_type);
}

//------------------------------------------------------------------------------
void DeregistrationRequestUeTerminated::SetDeregistrationType(
    uint8_t dereg_type) {
  ie_deregistration_type_.Set(dereg_type);
}

//------------------------------------------------------------------------------
void DeregistrationRequestUeTerminated::SetDeregistrationType(
    const _5gs_deregistration_type_t& type) {
  ie_deregistration_type_.Set(type);
}

//------------------------------------------------------------------------------
void DeregistrationRequestUeTerminated::Set5gmmCause(uint8_t value) {
  ie_5gmm_cause_ = std::make_optional<_5gmmCause>(kIei5gmmCause, value);
}

//------------------------------------------------------------------------------
std::optional<_5gmmCause> DeregistrationRequestUeTerminated::Get5gmmCause()
    const {
  return ie_5gmm_cause_;
}

//------------------------------------------------------------------------------
void DeregistrationRequestUeTerminated::SetT3346Value(uint8_t value) {
  ie_t3346_value_ = std::make_optional<GprsTimer2>(kT3346Value, value);
}

//------------------------------------------------------------------------------
std::optional<GprsTimer2> DeregistrationRequestUeTerminated::GetT3346Value()
    const {
  return ie_t3346_value_;
}

//------------------------------------------------------------------------------
void DeregistrationRequestUeTerminated::SetRejectedNssai(
    const std::vector<RejectedSNssai>& nssai) {
  if (nssai.size() > 0) {
    ie_rejected_nssai_ = std::make_optional<RejectedNssai>(kIeiRejectedNssaiDr);
    ie_rejected_nssai_.value().SetRejectedSNssais(nssai);
  }
}

std::optional<RejectedNssai>
DeregistrationRequestUeTerminated::GetRejectedNssai() const {
  return ie_rejected_nssai_;
}

//------------------------------------------------------------------------------
int DeregistrationRequestUeTerminated::Encode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Encoding DeregistrationRequestUeTerminated message");

  int encoded_size    = 0;
  int encoded_ie_size = 0;

  // Header
  if ((encoded_ie_size = ie_header_.Encode(buf, len)) == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Encoding NAS Header error");
    return KEncodeDecodeError;
  }
  encoded_size += encoded_ie_size;

  // De-registration Type and Spare half octet
  encoded_ie_size =
      NasHelper::Encode(ie_deregistration_type_, buf, len, encoded_size);
  // only 1/2 octet
  if ((encoded_ie_size == KEncodeDecodeError) or (encoded_ie_size != 0)) {
    return KEncodeDecodeError;
  }
  encoded_size++;  // 1/2 octet for Deregistration Type, 1/2 for Spare half
                   // octet

  // 5GMM Cause
  if ((encoded_ie_size = NasHelper::Encode(
           ie_5gmm_cause_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // T3346 value
  if ((encoded_ie_size = NasHelper::Encode(
           ie_t3346_value_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  // Rejected NSSAI
  if ((encoded_ie_size = NasHelper::Encode(
           ie_rejected_nssai_, buf, len, encoded_size)) == KEncodeDecodeError) {
    return KEncodeDecodeError;
  }
  // TODO: CagInformationList

  oai::logger::logger_common::nas().debug(
      "Encoded DeregistrationRequestUeTerminated message len (%d)",
      encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int DeregistrationRequestUeTerminated::Decode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Decoding DeregistrationRequestUeTerminated message");

  int decoded_size    = 0;
  int decoded_ie_size = 0;

  // Header
  decoded_ie_size = ie_header_.Decode(buf, len);
  if (decoded_ie_size == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Decoding NAS Header error");
    return KEncodeDecodeError;
  }
  decoded_size += decoded_ie_size;

  // De-registration Type +  Spare half octet
  decoded_ie_size =
      NasHelper::Decode(ie_deregistration_type_, buf, len, decoded_size, false);
  if ((decoded_ie_size == KEncodeDecodeError) or (decoded_ie_size != 0)) {
    return KEncodeDecodeError;
  }
  decoded_size++;  // 1/2 octet for De-registration Type, 1/2 for Spare half
                   // octet

  // Decode other IEs
  uint8_t octet = 0x00;
  DECODE_U8_VALUE(buf, octet, decoded_size, len);
  oai::logger::logger_common::nas().debug("First option IEI (0x%x)", octet);
  while ((octet != 0x0)) {
    switch (octet) {
      case kIei5gmmCause: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIei5gmmCause);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_5gmm_cause_, buf, len, decoded_size, true)) ==
            KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

      case kIeiGprsTimer2T3346: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiGprsTimer2T3346);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_t3346_value_, kIeiGprsTimer2T3346, buf, len, decoded_size,
                 true)) == KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

      case kIeiRejectedNssaiDr: {
        oai::logger::logger_common::nas().debug(
            "Decoding IEI 0x%x", kIeiRejectedNssaiDr);
        if ((decoded_ie_size = NasHelper::Decode(
                 ie_rejected_nssai_, kIeiRejectedNssaiDr, buf, len,
                 decoded_size, true)) == KEncodeDecodeError) {
          return KEncodeDecodeError;
        }
        DECODE_U8_VALUE(buf, octet, decoded_size, len);
        oai::logger::logger_common::nas().debug("Next IEI (0x%x)", octet);
      } break;

        // TODO: CagInformationList ie_cag_information_list ; //Optional

      default: {
        oai::logger::logger_common::nas().warn(
            "Unknown IEI 0x%x, stop decoding...", octet);
        // Stop decoding
        octet = 0x00;
      } break;
    }
  }

  oai::logger::logger_common::nas().debug(
      "Decoded DeregistrationRequestUeTerminated message (len %d)",
      decoded_size);
  return decoded_size;
}
