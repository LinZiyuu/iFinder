/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "Type4NasIe.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
Type4NasIe::Type4NasIe() : NasIe() {
  iei_ = std::nullopt;
  li_  = 0;
}

//------------------------------------------------------------------------------
Type4NasIe::Type4NasIe(uint8_t iei) : NasIe() {
  iei_ = std::make_optional<uint8_t>(iei);
  li_  = 0;
}

//------------------------------------------------------------------------------
// Type4NasIe::~Type4NasIe() {}

//------------------------------------------------------------------------------
void Type4NasIe::SetIei(uint8_t iei) {
  iei_ = std::make_optional<uint8_t>(iei);
}

//------------------------------------------------------------------------------
void Type4NasIe::GetIei(std::optional<uint8_t>& iei) const {
  iei = iei_;
}

//------------------------------------------------------------------------------
void Type4NasIe::SetLengthIndicator(uint8_t li) {
  li_ = li;
}

//------------------------------------------------------------------------------
void Type4NasIe::GetLengthIndicator(uint8_t& li) const {
  li = li_;
}

//------------------------------------------------------------------------------
uint8_t Type4NasIe::GetLengthIndicator() const {
  return li_;
}

//------------------------------------------------------------------------------
uint32_t Type4NasIe::GetIeLength() const {
  return (iei_.has_value() ? (li_ + 2) : (li_ + 1));  // 1 for IEI, 1 for Length
}

//------------------------------------------------------------------------------
uint8_t Type4NasIe::GetHeaderLength() const {
  return (iei_.has_value() ? 2 : 1);  // 1 for IEI, 1 for Length
}

//------------------------------------------------------------------------------
bool Type4NasIe::Validate(int len) const {
  uint32_t ie_len = GetIeLength();  // Length of the content + IEI/Len

  if (len < ie_len) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the length of this IE (%ld octet(s))",
        ie_len);
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool Type4NasIe::ValidateHeader(int len) const {
  int header_len = GetHeaderLength();  // Length of IEI/Len
  if (len < header_len) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the length of the header (IEI/Length) "
        "of "
        "this IE (%d octet(s))",
        header_len);
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
int Type4NasIe::Encode(uint8_t* buf, int len) const {
  if (!Validate(len)) return KEncodeDecodeError;

  int encoded_size = 0;
  uint8_t octet    = 0;
  if (iei_.has_value()) {
    ENCODE_U8(buf + encoded_size, iei_.value(), encoded_size);
  }

  ENCODE_U8(buf + encoded_size, li_, encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int Type4NasIe::Encode(uint8_t* buf, int len, int& len_pos) const {
  if (!Validate(len)) return KEncodeDecodeError;

  int encoded_size = 0;
  uint8_t octet    = 0;
  if (iei_.has_value()) {
    ENCODE_U8(buf + encoded_size, iei_.value(), encoded_size);
  }
  len_pos = encoded_size;
  encoded_size++;  // IE len will be encoded later
  return encoded_size;
}

//------------------------------------------------------------------------------
int Type4NasIe::Decode(const uint8_t* const buf, int len, bool is_iei) {
  if (!ValidateHeader(len)) return KEncodeDecodeError;

  int decoded_size = 0;
  uint8_t octet    = 0;

  if (is_iei) {
    DECODE_U8(buf + decoded_size, octet, decoded_size);
    iei_ = std::optional<uint8_t>(octet);
  }

  DECODE_U8(buf + decoded_size, li_, decoded_size);

  // after obtaining information for IEI/Length, validate the buffer size
  if (!Validate(len)) return KEncodeDecodeError;

  return decoded_size;
}
