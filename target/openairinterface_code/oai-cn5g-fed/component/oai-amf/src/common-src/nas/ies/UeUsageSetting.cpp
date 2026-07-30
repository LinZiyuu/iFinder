/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "UeUsageSetting.hpp"

#include "3gpp_24.501.hpp"
#include "IeConst.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
UeUsageSetting::UeUsageSetting() : Type4NasIe(kIeiUeUsageSetting) {
  ues_usage_setting_ = false;
  SetLengthIndicator(kUeUsageSettingContentLength);
}

//------------------------------------------------------------------------------
UeUsageSetting::UeUsageSetting(bool ues_usage_setting)
    : Type4NasIe(kIeiUeUsageSetting) {
  ues_usage_setting_ = ues_usage_setting;
  SetLengthIndicator(kUeUsageSettingContentLength);
}

//------------------------------------------------------------------------------
UeUsageSetting::~UeUsageSetting() {}

//------------------------------------------------------------------------------
void UeUsageSetting::SetValue(bool value) {
  ues_usage_setting_ = value;
}

//------------------------------------------------------------------------------
bool UeUsageSetting::GetValue() const {
  return ues_usage_setting_;
}

//------------------------------------------------------------------------------
int UeUsageSetting::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());

  int encoded_size = 0;
  // Validate the buffer's length and Encode IEI/Length
  int encoded_header_size = Type4NasIe::Encode(buf + encoded_size, len);
  if (encoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  encoded_size += encoded_header_size;

  ENCODE_U8(buf + encoded_size, 0x01 & ues_usage_setting_, encoded_size);

  oai::logger::logger_common::nas().debug(
      "Encoded %s, len (%d)", GetIeName().c_str(), encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int UeUsageSetting::Decode(const uint8_t* const buf, int len, bool is_iei) {
  oai::logger::logger_common::nas().debug("Decoding %s", GetIeName().c_str());

  if (len < kUeUsageSettingLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kUeUsageSettingLength);
    return KEncodeDecodeError;
  }

  int decoded_size = 0;

  // IEI and Length
  int decoded_header_size = Type4NasIe::Decode(buf + decoded_size, len, true);
  if (decoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  decoded_size += decoded_header_size;

  uint8_t octet = 0;
  DECODE_U8(buf + decoded_size, octet, decoded_size);

  ues_usage_setting_ = octet & 0x01;

  oai::logger::logger_common::nas().debug(
      "Decoded %s, UE's Usage Setting 0x%x, len %d", GetIeName().c_str(),
      ues_usage_setting_, decoded_size);
  return decoded_size;
}
