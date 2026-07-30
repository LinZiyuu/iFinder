/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "NetworkName.hpp"

#include "common_defs.hpp"
#include "conversions.hpp"
#include "logger_base.hpp"
#include "string.hpp"
#include "utils.hpp"

extern "C" {
#include "TLVDecoder.h"
#include "TLVEncoder.h"
}

using namespace oai::nas;

//------------------------------------------------------------------------------
NetworkName::NetworkName() : Type4NasIe() {
  coding_scheme_        = 0;
  add_ci_               = false;
  number_of_spare_bits_ = 0;
  text_string_          = nullptr;
  SetLengthIndicator(kNetworkNameContentMinimumLength);
}

//------------------------------------------------------------------------------
NetworkName::NetworkName(uint8_t iei) : Type4NasIe(iei) {
  coding_scheme_        = 0;
  add_ci_               = false;
  number_of_spare_bits_ = 0;
  text_string_          = nullptr;
  SetLengthIndicator(kNetworkNameContentMinimumLength);
}

//------------------------------------------------------------------------------
NetworkName::~NetworkName() {
  text_string_ = nullptr;
}

//------------------------------------------------------------------------------
void NetworkName::SetIei(uint8_t iei) {
  iei_ = iei;
}

//------------------------------------------------------------------------------
void NetworkName::NetworkName::SetCodingScheme(uint8_t value) {
  coding_scheme_ = value & 0x07;
}

//------------------------------------------------------------------------------
void NetworkName::SetAddCI(uint8_t value) {
  add_ci_ = value & 0x01;
}

//------------------------------------------------------------------------------
void NetworkName::SetNumberOfSpareBits(uint8_t value) {
  number_of_spare_bits_ = value & 0x07;
}

//------------------------------------------------------------------------------
void NetworkName::SetTextString(const std::string& str) {
  // TODO: Temporary for now
  // SMS Packing using "Seven characters in seven octets" (3GPP TS 23.038 )
  // str = "Testing";
  // std::string packed_str;
  // util::sms_packing(str, packed_str);
  // amf_conv::string_2_bstring(packed_str, text_string_);

  uint8_t* packed_str = (uint8_t*) calloc(7, sizeof(uint8_t));
  if (!packed_str) {
    oai::utils::utils::free_wrapper((void**) &packed_str);
    return;
  }
  // Text string = "Testing"
  packed_str[0] = 0xd4;
  packed_str[1] = 0xf2;
  packed_str[2] = 0x9c;
  packed_str[3] = 0x9e;
  packed_str[4] = 0x76;
  packed_str[5] = 0x9f;
  packed_str[6] = 0x01;

  text_string_ = blk2bstr(packed_str, 7);
  oai::utils::utils::free_wrapper((void**) &packed_str);
  SetLengthIndicator(1 + blength(text_string_));
}

//------------------------------------------------------------------------------
void NetworkName::SetTextString(const bstring& str) {
  text_string_ = bstrcpy(str);
  SetLengthIndicator(1 + blength(text_string_));
}

//------------------------------------------------------------------------------
int NetworkName::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding NetworkName");

  int encoded_size = 0;

  // Validate the buffer's length and Encode IEI/Length
  int encoded_header_size = Type4NasIe::Encode(buf + encoded_size, len);
  if (encoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  encoded_size += encoded_header_size;

  // Octet 3
  uint8_t octet = 0;
  // TODO: Extension (0x00 for now)
  octet = 0x00 | (coding_scheme_ << 4) | (add_ci_ << 3) | number_of_spare_bits_;
  ENCODE_U8(buf + encoded_size, octet, encoded_size);
  // Text String
  int size =
      encode_bstring(text_string_, (buf + encoded_size), len - encoded_size);
  encoded_size += size;

  oai::logger::logger_common::nas().debug(
      "Encoded NetworkName (len %d)", encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int NetworkName::Decode(const uint8_t* const buf, int len, bool is_iei) {
  // TODO: to be implemented
  return -1;
}
