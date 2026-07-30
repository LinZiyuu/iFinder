/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "_5gsDrxParameters.hpp"

#include "3gpp_24.501.hpp"
#include "IeConst.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
_5gsDrxParameters::_5gsDrxParameters(uint8_t value)
    : Type4NasIe(kIei5gsDrxParameters) {
  value_ = value & 0x0F;
  SetLengthIndicator(k5gsDrxParametersContentLength);
}

//------------------------------------------------------------------------------
_5gsDrxParameters::_5gsDrxParameters() {
  value_ = 0;
  SetLengthIndicator(k5gsDrxParametersContentLength);
}
_5gsDrxParameters::~_5gsDrxParameters() {}

//------------------------------------------------------------------------------
void _5gsDrxParameters::SetValue(uint8_t value) {
  value_ = value & 0x0F;
}

//------------------------------------------------------------------------------
uint8_t _5gsDrxParameters::GetValue() const {
  return value_;
}

//------------------------------------------------------------------------------
int _5gsDrxParameters::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());

  int encoded_size = 0;
  // Validate the buffer's length and Encode IEI/Length
  int encoded_header_size = Type4NasIe::Encode(buf + encoded_size, len);
  if (encoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  encoded_size += encoded_header_size;

  ENCODE_U8(buf + encoded_size, value_, encoded_size);

  oai::logger::logger_common::nas().debug(
      "Encoded %s, len (%d)", GetIeName().c_str(), encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int _5gsDrxParameters::Decode(const uint8_t* const buf, int len, bool is_iei) {
  oai::logger::logger_common::nas().debug("Decoding %s", GetIeName().c_str());

  if (len < k5gsDrxParametersLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        k5gsDrxParametersLength);
    return KEncodeDecodeError;
  }

  int decoded_size = 0;

  // IEI and Length
  int decoded_header_size = Type4NasIe::Decode(buf + decoded_size, len, true);
  if (decoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  decoded_size += decoded_header_size;

  uint8_t octet = 0;
  DECODE_U8(buf + decoded_size, octet, decoded_size);
  value_ = octet & 0x0f;

  oai::logger::logger_common::nas().debug(
      "Decoded %s, DRX value 0x%x, len %d", GetIeName().c_str(), value_,
      decoded_size);
  return decoded_size;
}
