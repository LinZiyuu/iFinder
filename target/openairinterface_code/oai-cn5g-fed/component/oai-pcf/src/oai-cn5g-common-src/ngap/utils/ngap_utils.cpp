/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "ngap_utils.hpp"

#include <fmt/format.h>

#include "conversions.hpp"
#include "logger_base.hpp"

namespace oai::ngap {
//------------------------------------------------------------------------------
void ngap_utils::print_asn_msg(
    const asn_TYPE_descriptor_t* td, const void* struct_ptr) {
  if (oai::logger::logger_registry::should_log(spdlog::level::debug))
    asn_fprint(stdout, td, struct_ptr);
}

//------------------------------------------------------------------------------
bool ngap_utils::octet_string_2_bstring(
    const OCTET_STRING_t& octet_str, bstring& b_str) {
  if (!octet_str.buf or (octet_str.size == 0)) return false;
  b_str = blk2bstr(octet_str.buf, octet_str.size);
  return true;
}

//------------------------------------------------------------------------------
bool ngap_utils::bstring_2_octet_string(
    const bstring& b_str, OCTET_STRING_t& octet_str) {
  if (!b_str) return false;
  OCTET_STRING_fromBuf(&octet_str, (char*) bdata(b_str), blength(b_str));
  return true;
}

//------------------------------------------------------------------------------
bool ngap_utils::bstring_2_bit_string(
    const bstring& b_str, BIT_STRING_t& bit_str) {
  int size = blength(b_str);
  if (!b_str or size <= 0) return false;
  if (!bdata(b_str)) return false;

  bit_str.buf = (uint8_t*) calloc(size + 1, sizeof(uint8_t));
  if (!bit_str.buf) return false;

  if (check_bstring(b_str))
    memcpy((void*) bit_str.buf, (char*) b_str->data, blength(b_str));
  ((uint8_t*) bit_str.buf)[size] = '\0';
  bit_str.size                   = size;
  bit_str.bits_unused            = 0;

  return true;
}

//------------------------------------------------------------------------------
void ngap_utils::sd_int_to_string_hex(uint32_t sd, std::string& sd_str) {
  sd_str = fmt::format("{0:06X}", sd);
}

//------------------------------------------------------------------------------
bool ngap_utils::check_bstring(const bstring& b_str) {
  if (b_str == nullptr || b_str->slen < 0 || b_str->data == nullptr)
    return false;
  return true;
}

//------------------------------------------------------------------------------
void ngap_utils::octet_string_2_string(
    const OCTET_STRING_t& octet_str, std::string& str) {
  if (!octet_str.buf or (octet_str.size == 0)) return;
  // std::string str_tmp((char *) octet_str.buf , octet_str.size);
  str.assign((char*) octet_str.buf, octet_str.size);
}

//------------------------------------------------------------------------------
void ngap_utils::string_2_octet_string(
    const std::string& str, OCTET_STRING_t& o_str) {
  o_str.buf = (uint8_t*) calloc(1, str.length() + 1);
  if (!o_str.buf) return;
  // o_str.buf = strcpy(new char[str.length() + 1], str.c_str());
  // memcpy(o_str.buf, str.c_str(), str.size());
  std::copy(str.begin(), str.end(), o_str.buf);
  o_str.size              = str.length();
  o_str.buf[str.length()] = '\0';  // just in case
}

//------------------------------------------------------------------------------
bool ngap_utils::int8_2_octet_string(uint8_t value, OCTET_STRING_t& o_str) {
  o_str.buf = (uint8_t*) calloc(1, sizeof(uint8_t));
  if (!o_str.buf) return false;
  o_str.size   = 1;
  o_str.buf[0] = value;
  return true;
}

//------------------------------------------------------------------------------
bool ngap_utils::octet_string_2_int8(
    const OCTET_STRING_t& o_str, uint8_t& value) {
  if (o_str.size != 1) return false;
  value = o_str.buf[0];
  return true;
}

//------------------------------------------------------------------------------
bool ngap_utils::octet_string_copy(
    OCTET_STRING_t& destination, const OCTET_STRING_t& source) {
  if (!source.buf) return false;
  OCTET_STRING_fromBuf(&destination, (char*) source.buf, source.size);
  return true;
}

//------------------------------------------------------------------------------
bool ngap_utils::check_octet_string(const OCTET_STRING_t& octet_str) {
  if (!octet_str.buf or (octet_str.size == 0)) return false;
  return true;
}

//------------------------------------------------------------------------------
bool ngap_utils::string_2_masked_imeisv(
    const std::string& imeisv_str, BIT_STRING_t& imeisv) {
  int len = imeisv_str.length();
  if (len != 16) return false;  // Must contain 16 digits

  imeisv.buf = (uint8_t*) calloc(8, sizeof(uint8_t));
  if (!imeisv.buf) {
    return false;
  }

  uint8_t digit_low  = 0;
  uint8_t digit_high = 0;

  int i = 0;
  int j = 0;
  while (i < len) {
    oai::utils::conv::string_to_int8(imeisv_str.substr(i, 1), digit_low);
    oai::utils::conv::string_to_int8(imeisv_str.substr(i + 1, 1), digit_high);
    i             = i + 2;
    uint8_t octet = (0xf0 & (digit_high << 4)) | (digit_low & 0x0f);
    imeisv.buf[j] = octet;
    j++;
  }
  // last 4 digits of the SNR masked by setting the corresponding bits to 1
  imeisv.buf[5] = 0xff;
  imeisv.buf[6] = 0xff;

  imeisv.size        = 8;
  imeisv.bits_unused = 0;
  return true;
}

}  // namespace oai::ngap
