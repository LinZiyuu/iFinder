/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "S1UeSecurityCapability.hpp"

#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
S1UeSecurityCapability::S1UeSecurityCapability() : Type4NasIe() {
  eea_ = 0;
  eia_ = 0;
  uea_ = std::nullopt;
  uia_ = std::nullopt;
  gea_ = std::nullopt;
  SetLengthIndicator(kS1UeSecurityCapabilityContentMinimumLength);
}

//------------------------------------------------------------------------------
S1UeSecurityCapability::S1UeSecurityCapability(uint8_t iei) : Type4NasIe(iei) {
  eea_ = 0;
  eia_ = 0;
  uea_ = std::nullopt;
  uia_ = std::nullopt;
  gea_ = std::nullopt;
  SetLengthIndicator(kS1UeSecurityCapabilityContentMinimumLength);
}

//------------------------------------------------------------------------------
S1UeSecurityCapability::S1UeSecurityCapability(
    uint8_t iei, uint8_t eea, uint8_t eia) {
  eea_ = eea;
  eia_ = eia;
  SetLengthIndicator(kS1UeSecurityCapabilityContentMinimumLength);
}

//------------------------------------------------------------------------------
S1UeSecurityCapability::S1UeSecurityCapability(
    uint8_t iei, uint8_t eea, uint8_t eia, uint8_t uea, uint8_t uia) {
  eea_ = eea;
  eia_ = eia;
  uea_ = std::optional<uint8_t>(uea);
  uia_ = std::optional<uint8_t>(uia);
  SetLengthIndicator(4);
}

//------------------------------------------------------------------------------
S1UeSecurityCapability::~S1UeSecurityCapability() {}

//------------------------------------------------------------------------------
void S1UeSecurityCapability::SetEea(uint8_t sel) {
  eea_ = sel;
}

//------------------------------------------------------------------------------
void S1UeSecurityCapability::SetEia(uint8_t sel) {
  eia_ = sel;
}

//------------------------------------------------------------------------------
uint8_t S1UeSecurityCapability::GetEea() const {
  return eea_;
}

//------------------------------------------------------------------------------
uint8_t S1UeSecurityCapability::GetEia() const {
  return eia_;
}

//------------------------------------------------------------------------------
void S1UeSecurityCapability::Set(uint8_t eea, uint8_t eia) {
  eea_ = eea;
  eia_ = eia;
  SetLengthIndicator(kS1UeSecurityCapabilityContentMinimumLength);
}

//------------------------------------------------------------------------------
void S1UeSecurityCapability::Get(uint8_t& eea, uint8_t& eia) const {
  eea = eea_;
  eia = eia_;
}

//------------------------------------------------------------------------------
void S1UeSecurityCapability::Set(
    uint8_t eea, uint8_t eia, uint8_t uea, uint8_t uia) {
  eea_ = eea;
  eia_ = eia;
  uea_ = std::optional<uint8_t>(uea);
  uia_ = std::optional<uint8_t>(uia);
  SetLengthIndicator(4);
}

//------------------------------------------------------------------------------
void S1UeSecurityCapability::Get(
    uint8_t& eea, uint8_t& eia, uint8_t& uea, uint8_t& uia) const {
  eea = eea_;
  eia = eia_;
  if (uea_.has_value()) uea = uea_.value();
  if (uia_.has_value()) uia = uia_.value();
}

//------------------------------------------------------------------------------
int S1UeSecurityCapability::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());

  int encoded_size = 0;
  // Validate the buffer's length and Encode IEI/Length
  int encoded_header_size = Type4NasIe::Encode(buf + encoded_size, len);
  if (encoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  encoded_size += encoded_header_size;

  // EEA
  ENCODE_U8(buf + encoded_size, eea_, encoded_size);
  // EIA
  ENCODE_U8(buf + encoded_size, eia_, encoded_size);

  // UEA
  if (uea_.has_value()) {
    ENCODE_U8(buf + encoded_size, uea_.value(), encoded_size);
  }
  // UIA
  if (uia_.has_value()) {
    ENCODE_U8(buf + encoded_size, uia_.value(), encoded_size);
  }

  // GEA
  if (gea_.has_value()) {
    ENCODE_U8(buf + encoded_size, gea_.value(), encoded_size);
  }

  oai::logger::logger_common::nas().debug(
      "Encoded %s, len (%d)", GetIeName().c_str(), encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int S1UeSecurityCapability::Decode(
    const uint8_t* const buf, int len, bool is_iei) {
  oai::logger::logger_common::nas().debug("Decoding %s", GetIeName().c_str());

  if (len < kS1UeSecurityCapabilityMinimumLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kS1UeSecurityCapabilityMinimumLength);
    return KEncodeDecodeError;
  }

  int decoded_size = 0;
  uint8_t octet    = 0;

  // IEI and Length
  int decoded_header_size = Type4NasIe::Decode(buf + decoded_size, len, is_iei);
  if (decoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  decoded_size += decoded_header_size;

  // EEA
  DECODE_U8(buf + decoded_size, eea_, decoded_size);
  // EIA
  DECODE_U8(buf + decoded_size, eia_, decoded_size);

  int ie_len = GetIeLength();

  // UEA
  if (ie_len > decoded_size) {
    DECODE_U8(buf + decoded_size, octet, decoded_size);
    uea_ = std::make_optional<uint8_t>(octet);
  }
  // UIA
  if (ie_len > decoded_size) {
    DECODE_U8(buf + decoded_size, octet, decoded_size);
    uia_ = std::make_optional<uint8_t>(octet & 0x7f);
  }
  // GEA
  if (ie_len > decoded_size) {
    DECODE_U8(buf + decoded_size, octet, decoded_size);
    gea_ = std::make_optional<uint8_t>(octet & 0x7f);
  }

  oai::logger::logger_common::nas().debug(
      "Decoded %s, len (%d)", GetIeName().c_str(), decoded_size);

  oai::logger::logger_common::nas().debug("EEA 0x%x, EIA 0x%x", eea_, eia_);

  if (uea_.has_value()) {
    oai::logger::logger_common::nas().debug("UEA 0x%x", uea_.value());
  }

  if (uia_.has_value()) {
    oai::logger::logger_common::nas().debug("UIA 0x%x", uia_.value());
  }

  if (gea_.has_value()) {
    oai::logger::logger_common::nas().debug("GEA 0x%x", gea_.value());
  }

  return decoded_size;
}
