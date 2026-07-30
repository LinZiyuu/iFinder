/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "MaximumNumberOfSupportedPacketFilters.hpp"

#include "3gpp_24.501.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"
using namespace oai::nas;

//------------------------------------------------------------------------------
MaximumNumberOfSupportedPacketFilters::MaximumNumberOfSupportedPacketFilters(
    uint8_t iei)
    : Type3NasIe(iei) {
  value_ = 0;
}

//------------------------------------------------------------------------------
MaximumNumberOfSupportedPacketFilters::MaximumNumberOfSupportedPacketFilters()
    : Type3NasIe() {
  value_ = 0;
}

//------------------------------------------------------------------------------
MaximumNumberOfSupportedPacketFilters::MaximumNumberOfSupportedPacketFilters(
    uint8_t iei, uint16_t value)
    : Type3NasIe(iei) {
  value_ = (value & 0xffe0);  // Get 11 bits of value
}

//------------------------------------------------------------------------------
MaximumNumberOfSupportedPacketFilters::
    ~MaximumNumberOfSupportedPacketFilters(){};

//------------------------------------------------------------------------------
uint32_t MaximumNumberOfSupportedPacketFilters::GetIeLength() const {
  return (
      kMaximumNumberOfSupportedPacketFiltersMaximumLength - 1 +
      Type3NasIe::GetIeLength());
}

//------------------------------------------------------------------------------
void MaximumNumberOfSupportedPacketFilters::SetValue(uint16_t value) {
  value_ = (value & 0xffe0);  // Get 11 bits of value
}

//------------------------------------------------------------------------------
uint16_t MaximumNumberOfSupportedPacketFilters::GetValue() const {
  return value_;
}

//------------------------------------------------------------------------------
void MaximumNumberOfSupportedPacketFilters::Set(uint8_t iei, uint16_t value) {
  SetIei(iei);
  value_ = (value & 0xffe0);  // Get 11 bits of value
}

//------------------------------------------------------------------------------
int MaximumNumberOfSupportedPacketFilters::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());

  if (len < kMaximumNumberOfSupportedPacketFiltersMinimumLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kMaximumNumberOfSupportedPacketFiltersMinimumLength);
    return KEncodeDecodeError;
  }
  int encoded_size = 0;

  // IEI
  encoded_size += Type3NasIe::Encode(buf + encoded_size, len);
  // Value
  ENCODE_U16(buf + encoded_size, value_, encoded_size);

  oai::logger::logger_common::nas().debug(
      "Encoded %s, len (%d)", GetIeName().c_str(), encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int MaximumNumberOfSupportedPacketFilters::Decode(
    const uint8_t* const buf, int len, bool is_iei) {
  oai::logger::logger_common::nas().debug("Decoding %s", GetIeName().c_str());

  if (len < kMaximumNumberOfSupportedPacketFiltersMinimumLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kMaximumNumberOfSupportedPacketFiltersMinimumLength);
    return KEncodeDecodeError;
  }

  int decoded_size = 0;
  // IEI and Length
  decoded_size += Type3NasIe::Decode(buf + decoded_size, len, is_iei);

  DECODE_U16(buf + decoded_size, value_, decoded_size);
  value_ = (value_ & 0xffe0);  // Get 11 bits of value

  oai::logger::logger_common::nas().debug("Decoded value 0x%x", value_);
  oai::logger::logger_common::nas().debug(
      "Decoded %s, len (%d)", GetIeName().c_str(), decoded_size);
  return decoded_size;
}
