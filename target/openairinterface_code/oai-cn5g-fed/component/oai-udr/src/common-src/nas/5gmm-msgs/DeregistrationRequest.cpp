/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "DeregistrationRequest.hpp"

#include "NasHelper.hpp"
#include "conversions.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
DeregistrationRequest::DeregistrationRequest()
    : ie_header_(
          k5gsMobilityManagementMessages, kPlain5gsMessage,
          kDeregistrationRequestUeOriginating) {}

//------------------------------------------------------------------------------
DeregistrationRequest::~DeregistrationRequest() {}

//------------------------------------------------------------------------------
uint32_t DeregistrationRequest::GetLength() const {
  uint32_t msg_len = 0;
  msg_len += ie_header_.GetLength();
  // msg_len += ie_deregistration_type_.GetIeLength();
  // msg_len += ie_ng_ksi_.GetIeLength();
  msg_len += 1;  // 1/2 for Deregistration type + 1/2 for ngKSI
  msg_len += ie_5gs_mobility_id_.GetIeLength();

  return msg_len;
}

//------------------------------------------------------------------------------
void DeregistrationRequest::SetHeader(uint8_t security_header_type) {
  ie_header_.SetSecurityHeaderType(security_header_type);
}

//------------------------------------------------------------------------------
void DeregistrationRequest::SetDeregistrationType(uint8_t dereg_type) {
  ie_deregistration_type_.Set(dereg_type);
}

//------------------------------------------------------------------------------
void DeregistrationRequest::SetDeregistrationType(
    const _5gs_deregistration_type_t& type) {
  ie_deregistration_type_.Set(type);
}

//------------------------------------------------------------------------------
void DeregistrationRequest::SetNgKsi(uint8_t tsc, uint8_t key_set_id) {
  ie_ng_ksi_.Set(true);  // high position
  ie_ng_ksi_.SetTypeOfSecurityContext(tsc);
  ie_ng_ksi_.SetNasKeyIdentifier(key_set_id);
}

//------------------------------------------------------------------------------
void DeregistrationRequest::GetDeregistrationType(uint8_t& dereg_type) const {
  ie_deregistration_type_.Get(dereg_type);
}

//------------------------------------------------------------------------------
void DeregistrationRequest::GetDeregistrationType(
    _5gs_deregistration_type_t& type) const {
  ie_deregistration_type_.Get(type);
}

//------------------------------------------------------------------------------
bool DeregistrationRequest::GetNgKsi(uint8_t& ng_ksi) const {
  ng_ksi = ie_ng_ksi_.GetNgKsi();
  return true;
}

//------------------------------------------------------------------------------
void DeregistrationRequest::SetSuciSupiFormatImsi(
    const std::string& mcc, const std::string& mnc,
    const std::string& routing_ind, uint8_t protection_sch_id,
    const std::string& msin) {
  if (protection_sch_id != kNullScheme) {
    oai::logger::logger_common::nas().error(
        "Encoding SUCI and SUPI format for IMSI error, please choose "
        "correct "
        "protection scheme");
    return;
  } else {
    ie_5gs_mobility_id_.SetSuciWithSupiImsi(
        mcc, mnc, routing_ind, protection_sch_id, msin);
  }
}

//------------------------------------------------------------------------------
void DeregistrationRequest::GetMobilityIdentityType(uint8_t& type) const {
  type = ie_5gs_mobility_id_.GetTypeOfIdentity();
}

//------------------------------------------------------------------------------
bool DeregistrationRequest::GetSuciSupiFormatImsi(SUCI_imsi_t& imsi) const {
  ie_5gs_mobility_id_.GetSuciWithSupiImsi(imsi);
  return true;
}

//------------------------------------------------------------------------------
std::string DeregistrationRequest::Get5gGuti() const {
  std::optional<_5G_GUTI_t> guti = std::nullopt;
  ie_5gs_mobility_id_.Get5gGuti(guti);
  if (!guti.has_value()) return {};

  std::string guti_str =
      guti.value().mcc + guti.value().mnc +
      std::to_string(guti.value().amf_region_id) +
      std::to_string(guti.value().amf_set_id) +
      std::to_string(guti.value().amf_pointer) +
      oai::utils::conv::tmsi_to_string(guti.value()._5g_tmsi);
  oai::logger::logger_common::nas().debug("5G GUTI %s", guti_str.c_str());
  return guti_str;
}

//------------------------------------------------------------------------------
void DeregistrationRequest::SetSuciSupiFormatImsi(
    const std::string& mcc, const std::string& mnc,
    const std::string& routing_ind, uint8_t protection_sch_id, uint8_t hnpki,
    const std::string& msin) {
  // TODO:
}

//------------------------------------------------------------------------------
void DeregistrationRequest::Set5gGuti() {}

//------------------------------------------------------------------------------
void DeregistrationRequest::SetImeiImeisv() {}

//------------------------------------------------------------------------------
void DeregistrationRequest::Set5gSTmsi() {}

//------------------------------------------------------------------------------
int DeregistrationRequest::Encode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Encoding DeregistrationRequest message");

  int encoded_size    = 0;
  int encoded_ie_size = 0;

  // Header
  if ((encoded_ie_size = ie_header_.Encode(buf, len)) == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Encoding NAS Header error");
    return KEncodeDecodeError;
  }
  encoded_size += encoded_ie_size;

  // De-registration Type and ngKSI
  encoded_ie_size =
      NasHelper::Encode(ie_deregistration_type_, buf, len, encoded_size);
  // only 1/2 octet
  if ((encoded_ie_size == KEncodeDecodeError) or (encoded_ie_size != 0)) {
    return KEncodeDecodeError;
  }
  encoded_ie_size = NasHelper::Encode(ie_ng_ksi_, buf, len, encoded_size);
  // only 1/2 octet
  if ((encoded_ie_size == KEncodeDecodeError) or (encoded_ie_size != 0)) {
    return KEncodeDecodeError;
  }
  encoded_size++;  // 1/2 octet for Deregistration Type, 1/2 for ngKSI

  // 5GS mobile identity
  if ((encoded_ie_size =
           NasHelper::Encode(ie_5gs_mobility_id_, buf, len, encoded_size)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  oai::logger::logger_common::nas().debug(
      "Encoded DeregistrationRequest message len (%d)", encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int DeregistrationRequest::Decode(uint8_t* buf, int len) {
  oai::logger::logger_common::nas().debug(
      "Decoding DeregistrationRequest message");

  int decoded_size    = 0;
  int decoded_ie_size = 0;

  // Header
  decoded_ie_size = ie_header_.Decode(buf, len);
  if (decoded_ie_size == KEncodeDecodeError) {
    oai::logger::logger_common::nas().error("Decoding NAS Header error");
    return KEncodeDecodeError;
  }
  decoded_size += decoded_ie_size;

  // De-registration Type + ngKSI
  decoded_ie_size =
      NasHelper::Decode(ie_deregistration_type_, buf, len, decoded_size, false);
  if ((decoded_ie_size == KEncodeDecodeError) or (decoded_ie_size != 0)) {
    return KEncodeDecodeError;
  }
  decoded_ie_size = NasHelper::Decode(
      ie_ng_ksi_, buf, len, decoded_size, true,
      false);  // 4 higher bits
  if ((decoded_ie_size == KEncodeDecodeError) or (decoded_ie_size != 0)) {
    return KEncodeDecodeError;
  }
  decoded_size++;  // 1/2 octet for De-registration Type, 1/2 ngKSI

  if ((decoded_ie_size = NasHelper::Decode(
           ie_5gs_mobility_id_, buf, len, decoded_size, false)) ==
      KEncodeDecodeError) {
    return KEncodeDecodeError;
  }

  oai::logger::logger_common::nas().debug(
      "Decoded DeregistrationRequest message (len %d)", decoded_size);
  return decoded_size;
}
