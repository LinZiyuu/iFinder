/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */
#include "Abba.hpp"

#include "3gpp_24.501.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
Abba::Abba() : Type4NasIe(), value_() {
  SetLengthIndicator(kAbbaContentMinimumLength);
}

//------------------------------------------------------------------------------
Abba::Abba(uint8_t iei) : Type4NasIe(iei), value_() {
  SetLengthIndicator(kAbbaContentMinimumLength);
}

//------------------------------------------------------------------------------
Abba::Abba(uint8_t length, uint8_t* value) : Type4NasIe() {
  for (int i = 0; i < length; i++) {
    this->value_[i] = value[i];
  }
  SetLengthIndicator(
      (length > kAbbaContentMinimumLength) ? length :
                                             kAbbaContentMinimumLength);
}

//------------------------------------------------------------------------------
Abba::Abba(uint8_t iei, uint8_t length, uint8_t* value) : Type4NasIe(iei) {
  for (int i = 0; i < length; i++) {
    this->value_[i] = value[i];
  }
  SetLengthIndicator(
      (length > kAbbaContentMinimumLength) ? length :
                                             kAbbaContentMinimumLength);
}

//------------------------------------------------------------------------------
Abba::~Abba() {}

//------------------------------------------------------------------------------
void Abba::Set(uint8_t length, const uint8_t* value) {
  for (int i = 0; i < length; i++) {
    this->value_[i] = value[i];
  }
  SetLengthIndicator(
      (length > kAbbaContentMinimumLength) ? length :
                                             kAbbaContentMinimumLength);
}

//------------------------------------------------------------------------------
void Abba::Set(uint8_t iei, uint8_t length, const uint8_t* value) {
  SetIei(iei);
  for (int i = 0; i < length; i++) {
    this->value_[i] = value[i];
  }
  SetLengthIndicator(
      (length > kAbbaContentMinimumLength) ? length :
                                             kAbbaContentMinimumLength);
}

//------------------------------------------------------------------------------
int Abba::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());

  int encoded_size = 0;
  // Validate the buffer's length and Encode IEI/Length
  int encoded_header_size = Type4NasIe::Encode(buf + encoded_size, len);
  if (encoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  encoded_size += encoded_header_size;
  int length = GetLengthIndicator();
  int i      = 0;
  while (length != 0) {
    ENCODE_U8(buf + encoded_size, value_[i], encoded_size);
    length--;
    i++;
  }

  oai::logger::logger_common::nas().debug(
      "Encoded %s, len (%d)", GetIeName().c_str(), encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int Abba::Decode(const uint8_t* const buf, int len, bool is_iei) {
  if (len < kAbbaMinimumLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kAbbaMinimumLength);
    return KEncodeDecodeError;
  }

  uint8_t decoded_size = 0;
  uint8_t octet        = 0;
  oai::logger::logger_common::nas().debug("Decoding %s", GetIeName().c_str());

  // IEI and Length
  int decoded_header_size = Type4NasIe::Decode(buf + decoded_size, len, is_iei);
  if (decoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  decoded_size += decoded_header_size;

  int i          = 0;
  uint8_t length = GetLengthIndicator();
  while (length != 0) {
    DECODE_U8(buf + decoded_size, value_[i], decoded_size);
    length--;
    i++;
  }

  for (int j = 0; j < GetLengthIndicator(); j++) {
    oai::logger::logger_common::nas().debug(
        "Decoded ABBA value (0x%4x)", value_[j]);
  }

  oai::logger::logger_common::nas().debug(
      "Decoded %s, len (%d)", GetIeName().c_str(), decoded_size);
  return decoded_size;
}
