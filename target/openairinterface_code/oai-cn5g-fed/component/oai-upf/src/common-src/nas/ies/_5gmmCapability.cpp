/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "_5gmmCapability.hpp"

#include "3gpp_24.501.hpp"
#include "IeConst.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
_5gmmCapability::_5gmmCapability(uint8_t iei, uint8_t octet3)
    : Type4NasIe(kIei5gmmCapability) {
  octet3_ = octet3;
  octet4_ = std::nullopt;
  octet5_ = std::nullopt;
  SetLengthIndicator(k5gmmCapabilityContentMinimumLength);
}

//------------------------------------------------------------------------------
_5gmmCapability::_5gmmCapability() : Type4NasIe(kIei5gmmCapability) {
  octet3_ = 0;
  octet4_ = std::nullopt;
  octet5_ = std::nullopt;
  SetLengthIndicator(k5gmmCapabilityContentMinimumLength);
}

//------------------------------------------------------------------------------
_5gmmCapability::~_5gmmCapability() {}

//------------------------------------------------------------------------------
void _5gmmCapability::SetOctet3(uint8_t iei, uint8_t octet3) {
  SetIei(iei);
  SetLengthIndicator(k5gmmCapabilityContentMinimumLength);
  octet3_ = octet3;
}

//------------------------------------------------------------------------------
uint8_t _5gmmCapability::GetOctet3() const {
  return octet3_;
}

//------------------------------------------------------------------------------
int _5gmmCapability::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());
  int ie_len = GetIeLength();

  int encoded_size = 0;
  // Validate the buffer's length and Encode IEI/Length
  int encoded_header_size = Type4NasIe::Encode(buf + encoded_size, len);
  if (encoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  encoded_size += encoded_header_size;

  // Octet 3
  ENCODE_U8(buf + encoded_size, octet3_, encoded_size);
  // TODO: Encode spare for the rest
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
int _5gmmCapability::Decode(const uint8_t* const buf, int len, bool is_iei) {
  if (len < k5gmmCapabilityMinimumLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        k5gmmCapabilityMinimumLength);
    return KEncodeDecodeError;
  }

  uint8_t decoded_size = 0;
  uint8_t octet        = 0;
  oai::logger::logger_common::nas().debug("Decoding %s", GetIeName().c_str());

  // IEI and Length
  int decoded_header_size = Type4NasIe::Decode(buf + decoded_size, len, is_iei);
  if (decoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  decoded_size += decoded_header_size;

  DECODE_U8(buf + decoded_size, octet3_, decoded_size);
  // TODO: decode the rest as spare for now
  uint8_t spare = 0;
  for (int i = 0; i < (GetLengthIndicator() - 1); i++) {
    DECODE_U8(buf + decoded_size, spare, decoded_size);
  }

  oai::logger::logger_common::nas().debug(
      "Decoded %s, Octet3 value (0x%x)", GetIeName().c_str(), octet3_);
  oai::logger::logger_common::nas().debug(
      "Decoded %s, len (%d)", GetIeName().c_str(), decoded_size);
  return decoded_size;
}
