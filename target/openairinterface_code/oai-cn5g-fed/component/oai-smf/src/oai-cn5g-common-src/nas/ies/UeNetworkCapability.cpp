/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "UeNetworkCapability.hpp"

#include "3gpp_24.501.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
UeNetworkCapability::UeNetworkCapability() : Type4NasIe() {
  eea_ = 0;
  eia_ = 0;
  SetLengthIndicator(kUeNetworkCapabilityContentMinimumLength);
}

//------------------------------------------------------------------------------
UeNetworkCapability::UeNetworkCapability(uint8_t iei) : Type4NasIe(iei) {
  eea_ = 0;
  eia_ = 0;
  SetLengthIndicator(kUeNetworkCapabilityContentMinimumLength);
}

//------------------------------------------------------------------------------
UeNetworkCapability::~UeNetworkCapability() {}

//------------------------------------------------------------------------------
UeNetworkCapability::UeNetworkCapability(uint8_t iei, uint8_t eea, uint8_t eia)
    : Type4NasIe(iei) {
  eea_ = eea;
  eia_ = eia;
  SetLengthIndicator(kUeNetworkCapabilityContentMinimumLength);
  oai::logger::logger_common::nas().debug(
      "Initialized %s EEA 0x%x, EIA 0x%x", GetIeName().c_str(), eea_, eia_);
}

//------------------------------------------------------------------------------
void UeNetworkCapability::SetEea(uint8_t value) {
  eea_ = value;
}

//------------------------------------------------------------------------------
void UeNetworkCapability::SetEia(uint8_t value) {
  eia_ = value;
}

//------------------------------------------------------------------------------
uint8_t UeNetworkCapability::GetEea() const {
  return eea_;
}

//------------------------------------------------------------------------------
uint8_t UeNetworkCapability::GetEia() const {
  return eia_;
}

//------------------------------------------------------------------------------
int UeNetworkCapability::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());
  int ie_len       = GetIeLength();
  int encoded_size = 0;

  // Validate the buffer's length and Encode IEI/Length
  int encoded_header_size = Type4NasIe::Encode(buf + encoded_size, len);
  if (encoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  encoded_size += encoded_header_size;

  // EEA
  ENCODE_U8(buf + encoded_size, eea_, encoded_size);
  // EIA
  ENCODE_U8(buf + encoded_size, eia_, encoded_size);

  // TODO: Encode the rest as spare for now
  uint8_t spare = 0;
  int spare_len = ie_len - encoded_size;
  for (int i = 0; i < spare_len; i++) {
    ENCODE_U8(buf + encoded_size, spare, encoded_size);
  }

  oai::logger::logger_common::nas().debug(
      "Encoded %s, len (%d)", GetIeName().c_str(), encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int UeNetworkCapability::Decode(
    const uint8_t* const buf, int len, bool is_iei) {
  oai::logger::logger_common::nas().debug("Decoding %s", GetIeName().c_str());

  if (len < kUeNetworkCapabilityMinimumLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kUeNetworkCapabilityMinimumLength);
    return KEncodeDecodeError;
  }

  int decoded_size = 0;

  // IEI and Length
  int decoded_header_size = Type4NasIe::Decode(buf + decoded_size, len, is_iei);
  if (decoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  decoded_size += decoded_header_size;

  DECODE_U8(buf + decoded_size, eea_, decoded_size);
  DECODE_U8(buf + decoded_size, eia_, decoded_size);

  int ie_len = GetIeLength();

  // TODO: decode the rest as spare for now
  uint8_t spare = 0;
  int spare_len = ie_len - decoded_size;
  for (int i = 0; i < spare_len; i++) {
    ENCODE_U8(buf + decoded_size, spare, decoded_size);
  }

  oai::logger::logger_common::nas().debug(
      "Decoded %s, len (%d)", GetIeName().c_str(), decoded_size);
  oai::logger::logger_common::nas().debug("EEA 0x%x, EIA 0x%x", eea_, eia_);
  return decoded_size;
}
