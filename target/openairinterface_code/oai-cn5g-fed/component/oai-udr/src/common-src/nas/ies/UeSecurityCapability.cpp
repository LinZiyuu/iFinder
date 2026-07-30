/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "UeSecurityCapability.hpp"

#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
UeSecurityCapability::UeSecurityCapability() : Type4NasIe() {
  _5g_ea_     = 0;
  _5g_ia_     = 0;
  eea_        = std::nullopt;
  eia_        = std::nullopt;
  octet_7_8_  = std::nullopt;
  octet_9_10_ = std::nullopt;
  SetLengthIndicator(kUeSecurityCapabilityContentMinimumLength);
}

//------------------------------------------------------------------------------
UeSecurityCapability::UeSecurityCapability(uint8_t iei) : Type4NasIe(iei) {
  _5g_ea_     = 0;
  _5g_ia_     = 0;
  eea_        = std::nullopt;
  eia_        = std::nullopt;
  octet_7_8_  = std::nullopt;
  octet_9_10_ = std::nullopt;
  SetLengthIndicator(kUeSecurityCapabilityContentMinimumLength);
}

//------------------------------------------------------------------------------
UeSecurityCapability::UeSecurityCapability(uint8_t _5g_ea, uint8_t _5g_ia)
    : Type4NasIe() {
  _5g_ea_     = _5g_ea;
  _5g_ia_     = _5g_ia;
  eea_        = std::nullopt;
  eia_        = std::nullopt;
  octet_7_8_  = std::nullopt;
  octet_9_10_ = std::nullopt;
  SetLengthIndicator(kUeSecurityCapabilityContentMinimumLength);
}

//------------------------------------------------------------------------------
UeSecurityCapability::UeSecurityCapability(
    uint8_t iei, uint8_t _5g_ea, uint8_t _5g_ia)
    : Type4NasIe(iei) {
  _5g_ea_     = _5g_ea;
  _5g_ia_     = _5g_ia;
  eea_        = std::nullopt;
  eia_        = std::nullopt;
  octet_7_8_  = std::nullopt;
  octet_9_10_ = std::nullopt;
  SetLengthIndicator(kUeSecurityCapabilityContentMinimumLength);
}

//------------------------------------------------------------------------------
UeSecurityCapability::UeSecurityCapability(
    uint8_t iei, uint8_t _5g_ea, uint8_t _5g_ia, uint8_t eea, uint8_t eia)
    : Type4NasIe(iei) {
  _5g_ea_     = _5g_ea;
  _5g_ia_     = _5g_ia;
  eea_        = std::optional<uint8_t>(eea);
  eia_        = std::optional<uint8_t>(eia);
  octet_7_8_  = std::nullopt;
  octet_9_10_ = std::nullopt;
  SetLengthIndicator(4);
}

//------------------------------------------------------------------------------
UeSecurityCapability::UeSecurityCapability(
    uint8_t _5g_ea, uint8_t _5g_ia, uint8_t eea, uint8_t eia)
    : Type4NasIe() {
  _5g_ea_     = _5g_ea;
  _5g_ia_     = _5g_ia;
  eea_        = std::optional<uint8_t>(eea);
  eia_        = std::optional<uint8_t>(eia);
  octet_7_8_  = std::nullopt;
  octet_9_10_ = std::nullopt;
  SetLengthIndicator(4);
}

//------------------------------------------------------------------------------
UeSecurityCapability::~UeSecurityCapability() {}

//------------------------------------------------------------------------------
void UeSecurityCapability::operator=(
    const UeSecurityCapability& ue_security_capability) {
  UeSecurityCapability m_ue_security_capability;
  _5g_ea_     = ue_security_capability.GetEa();
  _5g_ia_     = ue_security_capability.GetIa();
  uint8_t eea = 0;
  uint8_t eia = 0;

  if (ue_security_capability.GetEea(eea)) {
    eea_ = std::make_optional<uint8_t>(eea);
  }

  if (ue_security_capability.GetEia(eia)) {
    eia_ = std::make_optional<uint8_t>(eia);
  }
}

//------------------------------------------------------------------------------
void UeSecurityCapability::SetEa(uint8_t value) {
  _5g_ea_ = value;
}

//------------------------------------------------------------------------------
uint8_t UeSecurityCapability::GetEa() const {
  return _5g_ea_;
}

//------------------------------------------------------------------------------
void UeSecurityCapability::SetIa(uint8_t value) {
  _5g_ia_ = value;
}

//------------------------------------------------------------------------------
uint8_t UeSecurityCapability::GetIa() const {
  return _5g_ia_;
}

//------------------------------------------------------------------------------
void UeSecurityCapability::SetEea(uint8_t value) {
  eea_ = std::make_optional<uint8_t>(value);
}

//------------------------------------------------------------------------------
bool UeSecurityCapability::GetEea(uint8_t& value) const {
  if (eea_.has_value()) {
    value = eea_.value();
    return true;
  }
  return false;
}

//------------------------------------------------------------------------------
void UeSecurityCapability::GetEea(std::optional<uint8_t>& value) const {
  value = eea_;
}

//------------------------------------------------------------------------------
void UeSecurityCapability::SetEia(uint8_t value) {
  eia_ = std::make_optional<uint8_t>(value);
}

//------------------------------------------------------------------------------
bool UeSecurityCapability::GetEia(uint8_t& value) const {
  if (eia_.has_value()) {
    value = eia_.value();
    return true;
  }
  return false;
}

//------------------------------------------------------------------------------
void UeSecurityCapability::GetEia(std::optional<uint8_t>& value) const {
  value = eia_;
}

//------------------------------------------------------------------------------
void UeSecurityCapability::SetOctet_7_8(uint16_t value) {
  octet_7_8_ = std::make_optional<uint16_t>(value);
}

//------------------------------------------------------------------------------
void UeSecurityCapability::GetOctet_7_8(std::optional<uint16_t>& value) const {
  value = octet_7_8_;
}

//------------------------------------------------------------------------------
void UeSecurityCapability::SetOctet_9_10(uint16_t value) {
  octet_9_10_ = std::make_optional<uint16_t>(value);
}

//------------------------------------------------------------------------------
void UeSecurityCapability::GetOctet_9_10(std::optional<uint16_t>& value) const {
  value = octet_9_10_;
}

//------------------------------------------------------------------------------
void UeSecurityCapability::Set(uint8_t _5g_ea, uint8_t _5g_ia) {
  _5g_ea_ = _5g_ea;
  _5g_ia_ = _5g_ia;
}

//------------------------------------------------------------------------------
void UeSecurityCapability::Set(
    uint8_t _5g_ea, uint8_t _5g_ia, uint8_t eea, uint8_t eia) {
  _5g_ea_ = _5g_ea;
  _5g_ia_ = _5g_ia;
  eea_    = std::optional<uint8_t>(eea);
  eia_    = std::optional<uint8_t>(eia);
  SetLengthIndicator(4);
}

//------------------------------------------------------------------------------
int UeSecurityCapability::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());

  int encoded_size = 0;
  // Validate the buffer's length and Encode IEI/Length
  int encoded_header_size = Type4NasIe::Encode(buf + encoded_size, len);
  if (encoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  encoded_size += encoded_header_size;

  // EA
  ENCODE_U8(buf + encoded_size, _5g_ea_, encoded_size);
  // IA
  ENCODE_U8(buf + encoded_size, _5g_ia_, encoded_size);

  if (eea_.has_value()) {
    // EEA
    ENCODE_U8(buf + encoded_size, eea_.value(), encoded_size);
  }
  if (eia_.has_value()) {
    // EIA
    ENCODE_U8(buf + encoded_size, eia_.value(), encoded_size);
  }

  // Octet 7,8
  if (octet_7_8_.has_value()) {
    // EIA
    ENCODE_U16(buf + encoded_size, octet_7_8_.value(), encoded_size);
  }

  // Octet 9,10
  if (octet_9_10_.has_value()) {
    // EIA
    ENCODE_U16(buf + encoded_size, octet_9_10_.value(), encoded_size);
  }

  oai::logger::logger_common::nas().debug(
      "Encoded %s, len (%d)", GetIeName().c_str(), encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int UeSecurityCapability::Decode(
    const uint8_t* const buf, int len, bool is_iei) {
  oai::logger::logger_common::nas().debug("Decoding %s", GetIeName().c_str());

  if (len < kUeSecurityCapabilityMinimumLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kUeSecurityCapabilityMinimumLength);
    return KEncodeDecodeError;
  }

  int decoded_size = 0;
  uint8_t octet    = 0;

  // IEI and Length
  int decoded_header_size = Type4NasIe::Decode(buf + decoded_size, len, is_iei);
  if (decoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  decoded_size += decoded_header_size;
  // EA
  DECODE_U8(buf + decoded_size, _5g_ea_, decoded_size);
  // IA
  DECODE_U8(buf + decoded_size, _5g_ia_, decoded_size);

  int ie_len = GetIeLength();
  if (ie_len > decoded_size) {
    // EEA
    DECODE_U8(buf + decoded_size, octet, decoded_size);
    eea_ = std::make_optional<uint8_t>(octet);
  }

  if (ie_len > decoded_size) {
    // EIA
    DECODE_U8(buf + decoded_size, octet, decoded_size);
    eia_ = std::make_optional<uint8_t>(octet);
  }

  // TODO: decode the rest as spare for now
  uint16_t spare = 0;
  if (ie_len > (decoded_size + 1)) {
    // Octet 7,8
    DECODE_U16(buf + decoded_size, spare, decoded_size);
    octet_7_8_ = std::make_optional<uint16_t>(spare);
  }

  if (ie_len > (decoded_size + 1)) {
    // Octet 9,10
    DECODE_U16(buf + decoded_size, spare, decoded_size);
    octet_9_10_ = std::make_optional<uint16_t>(spare);
  }

  oai::logger::logger_common::nas().debug(
      "Decoded %s, len (%d)", GetIeName().c_str(), decoded_size);

  oai::logger::logger_common::nas().debug(
      "5G EA 0x%x, 5G IA 0x%x", _5g_ea_, _5g_ia_);
  if (eea_.has_value()) {
    oai::logger::logger_common::nas().debug("EEA 0x%x", eea_.value());
  }

  if (eia_.has_value()) {
    oai::logger::logger_common::nas().debug("EIA 0x%x", eia_.value());
  }

  return decoded_size;
}
