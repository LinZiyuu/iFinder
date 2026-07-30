/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "UeRadioCapabilityId.hpp"

#include "3gpp_24.501.hpp"
#include "IeConst.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
UeRadioCapabilityId::UeRadioCapabilityId()
    : Type4NasIe(kIeiUeRadioCapabilityId), value_() {
  SetLengthIndicator(kUeRadioCapabilityIdContentMinimumLength);
}

//------------------------------------------------------------------------------
UeRadioCapabilityId::UeRadioCapabilityId(const bstring& value)
    : Type4NasIe(kIeiUeRadioCapabilityId) {
  value_ = bstrcpy(value);
  SetLengthIndicator(
      (blength(value_) > kUeRadioCapabilityIdContentMinimumLength) ?
          blength(value_) :
          kUeRadioCapabilityIdContentMinimumLength);
}

//------------------------------------------------------------------------------
UeRadioCapabilityId::~UeRadioCapabilityId() {}

//------------------------------------------------------------------------------
void UeRadioCapabilityId::SetValue(const bstring& value) {
  value_ = bstrcpy(value);
  SetLengthIndicator(
      (blength(value_) > kUeRadioCapabilityIdContentMinimumLength) ?
          blength(value_) :
          kUeRadioCapabilityIdContentMinimumLength);
}

//------------------------------------------------------------------------------
void UeRadioCapabilityId::GetValue(bstring& value) const {
  value = bstrcpy(value_);
}

//------------------------------------------------------------------------------
int UeRadioCapabilityId::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());
  int encoded_size = 0;

  // Validate the buffer's length and Encode IEI, Length (later)
  int len_pos = 0;
  int encoded_header_size =
      Type4NasIe::Encode(buf + encoded_size, len, len_pos);
  if (encoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  encoded_size += encoded_header_size;

  // Value
  int size = encode_bstring(value_, (buf + encoded_size), len - encoded_size);
  encoded_size += size;

  // Encode length
  int encoded_len_ie = 0;
  ENCODE_U16(buf + len_pos, encoded_size - GetHeaderLength(), encoded_len_ie);

  oai::logger::logger_common::nas().debug(
      "Encoded %s, len (%d)", GetIeName().c_str(), encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int UeRadioCapabilityId::Decode(
    const uint8_t* const buf, int len, bool is_iei) {
  oai::logger::logger_common::nas().debug("Decoding %s", GetIeName().c_str());
  int decoded_size = 0;

  // IEI and Length
  int decoded_header_size = Type4NasIe::Decode(buf + decoded_size, len, is_iei);
  if (decoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  decoded_size += decoded_header_size;
  uint16_t ie_len = 0;
  ie_len          = GetLengthIndicator();

  if (len < GetIeLength()) {
    oai::logger::logger_common::nas().error(
        "Len is less than %d", GetIeLength());
    return KEncodeDecodeError;
  }

  // Value
  decode_bstring(&value_, ie_len, (buf + decoded_size), len - decoded_size);
  decoded_size += ie_len;
  for (int i = 0; i < ie_len; i++) {
    oai::logger::logger_common::nas().debug(
        "Decoded NasMessageContainer value 0x%x", (uint8_t) value_->data[i]);
  }

  oai::logger::logger_common::nas().debug(
      "Decoded %s, len (%d)", GetIeName().c_str(), decoded_size);
  return decoded_size;
}
