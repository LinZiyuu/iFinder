/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "GprsTimer.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
GprsTimer::GprsTimer(uint8_t iei) : Type3NasIe(iei), value_() {}

//------------------------------------------------------------------------------
GprsTimer::GprsTimer(uint8_t iei, uint8_t unit, uint8_t value)
    : Type3NasIe(iei) {
  unit_  = unit;
  value_ = value;
}

//------------------------------------------------------------------------------
GprsTimer::~GprsTimer() {}

//------------------------------------------------------------------------------
uint32_t GprsTimer::GetIeLength() const {
  return (kGprsTimerLength - 1 + Type3NasIe::GetIeLength());
}

//------------------------------------------------------------------------------
void GprsTimer::Set(uint8_t iei, uint8_t unit, uint8_t value) {
  SetIei(iei);
  unit_  = unit;
  value_ = value;
}

//------------------------------------------------------------------------------
void GprsTimer::SetUnit(uint8_t unit) {
  if (unit > 0x07) return;  // 3 bits
  unit_ = unit;
}

//------------------------------------------------------------------------------
uint8_t GprsTimer::GetUnit() const {
  return unit_;
}

//------------------------------------------------------------------------------
void GprsTimer::SetValue(uint8_t value) {
  if (value > 0x1f) return;  // 5 bits
  value_ = value;
}

//------------------------------------------------------------------------------
uint8_t GprsTimer::GetValue() const {
  return value_;
}

//------------------------------------------------------------------------------
int GprsTimer::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());

  if (len < kGprsTimerLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kGprsTimerLength);
    return KEncodeDecodeError;
  }

  int encoded_size = 0;
  // IEI
  encoded_size += Type3NasIe::Encode(buf + encoded_size, len);
  // Unit+Value
  uint8_t octet_2 = ((unit_ & 0x07) << 5) | (value_ & 0x1f);
  ENCODE_U8(buf + encoded_size, octet_2, encoded_size);

  oai::logger::logger_common::nas().debug(
      "Encoded %s, len (%d)", GetIeName().c_str(), encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int GprsTimer::Decode(const uint8_t* const buf, int len, bool is_iei) {
  if (len < kGprsTimerLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kGprsTimerLength);
    return KEncodeDecodeError;
  }

  uint8_t decoded_size = 0;
  // IEI
  decoded_size += Type3NasIe::Decode(buf + decoded_size, len, is_iei);
  // Unit+Value
  uint8_t octet_2 = 0;
  DECODE_U8(buf + decoded_size, octet_2, decoded_size);
  unit_  = (octet_2 >> 5) & 0x07;
  value_ = octet_2 & 0x1f;
  oai::logger::logger_common::nas().debug(
      "Decoded %s, Unit 0x%x, Value 0x%x", GetIeName().c_str(), unit_, value_);

  oai::logger::logger_common::nas().debug(
      "Decoded %s, len (%d)", GetIeName().c_str(), decoded_size);
  return decoded_size;
}
