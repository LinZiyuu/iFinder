/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_NGAP_UTILS_HPP_SEEN
#define FILE_NGAP_UTILS_HPP_SEEN

#include "logger_base.hpp"
#include "utils.hpp"

extern "C" {
#include "BIT_STRING.h"
#include "OCTET_STRING.h"
#include "constr_TYPE.h"
}

namespace oai::ngap {
class ngap_utils {
 public:
  static void print_asn_msg(
      const asn_TYPE_descriptor_t* td, const void* struct_ptr);
  static bool octet_string_2_bstring(
      const OCTET_STRING_t& octet_str, bstring& b_str);
  static bool bstring_2_octet_string(
      const bstring& b_str, OCTET_STRING_t& octet_str);
  static bool bstring_2_bit_string(const bstring& b_str, BIT_STRING_t& bit_str);
  static void sd_int_to_string_hex(uint32_t sd, std::string& sd_str);
  static bool check_bstring(const bstring& b_str);
  static void octet_string_2_string(
      const OCTET_STRING_t& octet_str, std::string& str);
  static void string_2_octet_string(
      const std::string& str, OCTET_STRING_t& o_str);
  static bool int8_2_octet_string(uint8_t value, OCTET_STRING_t& o_str);
  static bool octet_string_2_int8(const OCTET_STRING_t& o_str, uint8_t& value);
  static bool octet_string_copy(
      OCTET_STRING_t& destination, const OCTET_STRING_t& source);
  static bool check_octet_string(const OCTET_STRING_t& octet_str);
  static bool string_2_masked_imeisv(
      const std::string& str, BIT_STRING_t& imeisv);
};
}  // namespace oai::ngap
#endif /* FILE_NGAP_UTILS_HPP_SEEN */
