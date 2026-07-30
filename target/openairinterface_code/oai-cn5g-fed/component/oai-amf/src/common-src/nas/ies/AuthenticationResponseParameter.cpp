/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "AuthenticationResponseParameter.hpp"

#include "logger_base.hpp"
using namespace oai::nas;

//------------------------------------------------------------------------------
AuthenticationResponseParameter::AuthenticationResponseParameter()
    : Type4NasIe(kIeiAuthenticationResponseParameter), res_or_res_star_() {
  SetLengthIndicator(kAuthenticationResponseParameterContentMinimumLength);
}

//------------------------------------------------------------------------------
AuthenticationResponseParameter::AuthenticationResponseParameter(
    const bstring& para)
    : Type4NasIe(kIeiAuthenticationResponseParameter) {
  res_or_res_star_ = bstrcpy(para);
  SetLengthIndicator(
      (blength(res_or_res_star_) >
       kAuthenticationResponseParameterContentMinimumLength) ?
          blength(res_or_res_star_) :
          kAuthenticationResponseParameterContentMinimumLength);
}

//------------------------------------------------------------------------------
AuthenticationResponseParameter::~AuthenticationResponseParameter() {}

//------------------------------------------------------------------------------
void AuthenticationResponseParameter::SetValue(const bstring& para) {
  res_or_res_star_ = bstrcpy(para);
  SetLengthIndicator(
      (blength(res_or_res_star_) >
       kAuthenticationResponseParameterContentMinimumLength) ?
          blength(res_or_res_star_) :
          kAuthenticationResponseParameterContentMinimumLength);
}

//------------------------------------------------------------------------------
void AuthenticationResponseParameter::GetValue(bstring& para) const {
  para = bstrcpy(res_or_res_star_);
}

//------------------------------------------------------------------------------
int AuthenticationResponseParameter::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());

  int encoded_size = 0;
  // Validate the buffer's length and Encode IEI/Length
  int encoded_header_size = Type4NasIe::Encode(buf + encoded_size, len);
  if (encoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  encoded_size += encoded_header_size;

  // Value
  int size = encode_bstring(
      res_or_res_star_, (buf + encoded_size), len - encoded_size);
  encoded_size += size;

  oai::logger::logger_common::nas().debug(
      "Encoded %s, len (%d)", GetIeName().c_str(), encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int AuthenticationResponseParameter::Decode(
    const uint8_t* const buf, int len, bool is_iei) {
  if (len < kAuthenticationResponseParameterMinimumLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kAuthenticationResponseParameterMinimumLength);
    return KEncodeDecodeError;
  }

  uint8_t decoded_size = 0;
  uint8_t octet        = 0;
  oai::logger::logger_common::nas().debug("Decoding %s", GetIeName().c_str());

  // IEI and Length
  int decoded_header_size = Type4NasIe::Decode(buf + decoded_size, len, is_iei);
  if (decoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  decoded_size += decoded_header_size;

  // RES or RES*
  uint8_t ie_len = GetLengthIndicator();
  decode_bstring(
      &res_or_res_star_, ie_len, (buf + decoded_size), len - decoded_size);
  decoded_size += ie_len;

  for (int i = 0; i < ie_len; i++) {
    oai::logger::logger_common::nas().debug(
        "Decoded value 0x%x", (uint8_t) res_or_res_star_->data[i]);
  }

  oai::logger::logger_common::nas().debug(
      "Decoded %s, len (%d)", GetIeName().c_str(), decoded_size);
  return decoded_size;
}
