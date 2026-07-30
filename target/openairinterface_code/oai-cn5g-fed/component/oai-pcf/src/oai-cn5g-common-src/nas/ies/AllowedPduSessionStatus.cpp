/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "AllowedPduSessionStatus.hpp"

#include "3gpp_24.501.hpp"
#include "IeConst.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
AllowedPduSessionStatus::AllowedPduSessionStatus()
    : Type4NasIe(kIeiAllowedPduSessionStatus) {
  value_ = 0;
  SetLengthIndicator(kAllowedPduSessionStatusContentMinimumLength);
}

//------------------------------------------------------------------------------
AllowedPduSessionStatus::AllowedPduSessionStatus(uint16_t value)
    : Type4NasIe(kIeiAllowedPduSessionStatus) {
  value_ = value;
  SetLengthIndicator(kAllowedPduSessionStatusContentMinimumLength);
}

//------------------------------------------------------------------------------
AllowedPduSessionStatus::~AllowedPduSessionStatus() {}

//------------------------------------------------------------------------------
void AllowedPduSessionStatus::SetValue(uint16_t value) {
  value_ = value;
}

//------------------------------------------------------------------------------
uint16_t AllowedPduSessionStatus::GetValue() const {
  return value_;
}

//------------------------------------------------------------------------------
int AllowedPduSessionStatus::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());
  int ie_len = GetIeLength();

  int encoded_size = 0;
  // Validate the buffer's length and Encode IEI/Length
  int encoded_header_size = Type4NasIe::Encode(buf + encoded_size, len);
  if (encoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  encoded_size += encoded_header_size;

  ENCODE_U16(buf + encoded_size, value_, encoded_size);

  // TODO: Encode spare for the rest
  uint8_t spare = 0;
  int spare_len = ie_len - encoded_size;
  for (int i = 0; i < spare_len; i++) {
    ENCODE_U8(buf + encoded_size, spare, encoded_size);
  }

  oai::logger::logger_common::nas().debug(
      "Decoded %s, len (%d)", GetIeName().c_str(), encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int AllowedPduSessionStatus::Decode(
    const uint8_t* const buf, int len, bool is_iei) {
  if (len < kAllowedPduSessionStatusMinimumLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kAllowedPduSessionStatusMinimumLength);
    return KEncodeDecodeError;
  }

  uint8_t decoded_size = 0;
  uint8_t octet        = 0;
  oai::logger::logger_common::nas().debug("Decoding %s", GetIeName().c_str());

  // IEI and Length
  int decoded_header_size = Type4NasIe::Decode(buf + decoded_size, len, is_iei);
  if (decoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  decoded_size += decoded_header_size;

  DECODE_U16(buf + decoded_size, value_, decoded_size);

  // TODO: decode the rest as spare for now
  uint8_t spare = 0;
  int spare_len = GetLengthIndicator() - sizeof(uint16_t);
  for (int i = 0; i < spare_len; i++) {
    DECODE_U8(buf + decoded_size, spare, decoded_size);
  }

  oai::logger::logger_common::nas().debug(
      "Decoded %s (value 0x%4x)", GetIeName().c_str(), value_);
  oai::logger::logger_common::nas().debug(
      "Decoded %s, len (%d)", GetIeName().c_str(), decoded_size);
  return decoded_size;
}
