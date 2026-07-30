/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "GprsTimer2.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
GprsTimer2::GprsTimer2(uint8_t iei) : Type4NasIe(iei), value_() {
  SetLengthIndicator(kGprsTimer2ContentLength);
}

//------------------------------------------------------------------------------
GprsTimer2::GprsTimer2(uint8_t iei, uint8_t value) : Type4NasIe(iei) {
  value_ = value;
  SetLengthIndicator(kGprsTimer2ContentLength);
}

//------------------------------------------------------------------------------
// GprsTimer2::~GprsTimer2() {}

//------------------------------------------------------------------------------
void GprsTimer2::SetValue(uint8_t value) {
  value_ = value;
}

//------------------------------------------------------------------------------
uint8_t GprsTimer2::GetValue() const {
  return value_;
}

//------------------------------------------------------------------------------
int GprsTimer2::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());

  int encoded_size = 0;
  // Validate the buffer's length and Encode IEI/Length
  int encoded_header_size = Type4NasIe::Encode(buf + encoded_size, len);
  if (encoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  encoded_size += encoded_header_size;

  // Octet 3
  ENCODE_U8(buf + encoded_size, value_, encoded_size);

  oai::logger::logger_common::nas().debug(
      "Encoded %s, len (%d)", GetIeName().c_str(), encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int GprsTimer2::Decode(const uint8_t* const buf, int len, bool is_iei) {
  if (len < kGprsTimer2Length) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kGprsTimer2Length);
    return KEncodeDecodeError;
  }

  uint8_t decoded_size = 0;
  uint8_t octet        = 0;
  oai::logger::logger_common::nas().debug("Decoding %s", GetIeName().c_str());

  // IEI and Length
  int decoded_header_size = Type4NasIe::Decode(buf + decoded_size, len, is_iei);
  if (decoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  decoded_size += decoded_header_size;

  DECODE_U8(buf + decoded_size, value_, decoded_size);

  oai::logger::logger_common::nas().debug(
      "Decoded %s, Value 0x%x", GetIeName().c_str(), value_);
  oai::logger::logger_common::nas().debug(
      "Decoded %s, len (%d)", GetIeName().c_str(), decoded_size);
  return decoded_size;
}
