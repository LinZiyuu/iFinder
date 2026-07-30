/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "AuthenticationFailureParameter.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
AuthenticationFailureParameter::AuthenticationFailureParameter()
    : Type4NasIe(kIeiAuthenticationFailureParameter), value_() {
  SetLengthIndicator(kAuthenticationFailureParameterContentLength);
}

//------------------------------------------------------------------------------
AuthenticationFailureParameter::AuthenticationFailureParameter(
    const bstring& value) {
  value_ = bstrcpy(value);
  SetLengthIndicator(kAuthenticationFailureParameterContentLength);
}

//------------------------------------------------------------------------------
// AuthenticationFailureParameter::~AuthenticationFailureParameter() {}

//------------------------------------------------------------------------------
void AuthenticationFailureParameter::SetValue(const bstring& value) {
  value_ = bstrcpy(value);
  SetLengthIndicator(kAuthenticationFailureParameterContentLength);
}

//------------------------------------------------------------------------------
void AuthenticationFailureParameter::GetValue(bstring& value) const {
  value = bstrcpy(value_);
}

//------------------------------------------------------------------------------
int AuthenticationFailureParameter::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());

  int encoded_size = 0;
  // Validate the buffer's length and Encode IEI/Length
  int encoded_header_size = Type4NasIe::Encode(buf + encoded_size, len);
  if (encoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  encoded_size += encoded_header_size;

  int size = encode_bstring(value_, (buf + encoded_size), len - encoded_size);
  encoded_size += size;

  oai::logger::logger_common::nas().debug(
      "Encoded %s, len (%d)", GetIeName().c_str(), encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int AuthenticationFailureParameter::Decode(
    const uint8_t* const buf, int len, bool is_iei) {
  uint8_t decoded_size = 0;
  uint8_t octet        = 0;
  oai::logger::logger_common::nas().debug("Decoding %s", GetIeName().c_str());

  // IEI and Length
  int decoded_header_size = Type4NasIe::Decode(buf + decoded_size, len, is_iei);
  if (decoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  decoded_size += decoded_header_size;

  if (GetLengthIndicator() != kAuthenticationFailureParameterContentLength)
    return KEncodeDecodeError;

  // Value
  uint8_t ie_len = GetLengthIndicator();
  decode_bstring(&value_, ie_len, (buf + decoded_size), len - decoded_size);
  decoded_size += ie_len;

  for (int i = 0; i < ie_len; i++) {
    oai::logger::logger_common::nas().debug(
        "Decoded value 0x%x", (uint8_t) value_->data[i]);
  }

  oai::logger::logger_common::nas().debug(
      "Decoded %s, len (%d)", GetIeName().c_str(), decoded_size);
  return decoded_size;
}
