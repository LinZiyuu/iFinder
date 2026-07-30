/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "ExtendedDrxParameters.hpp"

#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
ExtendedDrxParameters::ExtendedDrxParameters()
    : Type4NasIe(kIeiExtendedDrxParameters), paging_time_(), e_drx_value_() {
  SetLengthIndicator(kExtendedDrxParametersContentLength);
}

//------------------------------------------------------------------------------
ExtendedDrxParameters::ExtendedDrxParameters(uint8_t paging_time, uint8_t value)
    : Type4NasIe(kIeiExtendedDrxParameters) {
  paging_time_ = paging_time & 0x0F;
  e_drx_value_ = value & 0x0F;
  SetLengthIndicator(kExtendedDrxParametersContentLength);
}

//------------------------------------------------------------------------------
ExtendedDrxParameters::~ExtendedDrxParameters() {}

//------------------------------------------------------------------------------
void ExtendedDrxParameters::SetValue(uint8_t value) {
  e_drx_value_ = value & 0x0F;
}

//------------------------------------------------------------------------------
void ExtendedDrxParameters::SetPagingTime(uint8_t value) {
  paging_time_ = value & 0x0F;
}

//------------------------------------------------------------------------------
uint8_t ExtendedDrxParameters::GetValue() const {
  return e_drx_value_;
}

//------------------------------------------------------------------------------
uint8_t ExtendedDrxParameters::GetPagingTime() const {
  return paging_time_;
}

//------------------------------------------------------------------------------
int ExtendedDrxParameters::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());

  int encoded_size = 0;
  // Validate the buffer's length and Encode IEI/Length
  int encoded_header_size = Type4NasIe::Encode(buf + encoded_size, len);
  if (encoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  encoded_size += encoded_header_size;

  // Octet 3
  uint8_t octet = (0x0F & e_drx_value_) | ((paging_time_ & 0x0f) << 4);
  ENCODE_U8(buf + encoded_size, octet, encoded_size);

  oai::logger::logger_common::nas().debug(
      "Encoded %s, len (%d)", GetIeName().c_str(), encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int ExtendedDrxParameters::Decode(
    const uint8_t* const buf, int len, bool is_iei) {
  if (len < kExtendedDrxParametersLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kExtendedDrxParametersLength);
    return KEncodeDecodeError;
  }

  uint8_t decoded_size = 0;
  uint8_t octet        = 0;
  oai::logger::logger_common::nas().debug("Decoding %s", GetIeName().c_str());

  // IEI and Length
  int decoded_header_size = Type4NasIe::Decode(buf + decoded_size, len, is_iei);
  if (decoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  decoded_size += decoded_header_size;

  DECODE_U8(buf + decoded_size, octet, decoded_size);

  e_drx_value_ = octet & 0x0f;
  paging_time_ = (octet & 0xf0) >> 4;

  oai::logger::logger_common::nas().debug(
      "Decoded %s, Paging Time Window 0x%x, eDRX value 0x%x",
      GetIeName().c_str(), paging_time_, e_drx_value_);
  oai::logger::logger_common::nas().debug(
      "Decoded %s, len (%d)", GetIeName().c_str(), decoded_size);
  return decoded_size;
}
