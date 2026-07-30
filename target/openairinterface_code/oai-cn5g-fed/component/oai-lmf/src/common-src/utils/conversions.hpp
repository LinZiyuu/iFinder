/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_CONVERSIONS_HPP_SEEN
#define FILE_CONVERSIONS_HPP_SEEN

#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string>

namespace oai::utils {

class conv {
 public:
  static void hexa_to_ascii(uint8_t* from, char* to, size_t length);
  static int ascii_to_hex(uint8_t* dst, const char* h);
  static struct in_addr fromString(const std::string& addr4);
  static struct in6_addr fromStringV6(const std::string& addr6);
  static std::string toString(const struct in_addr& inaddr);
  static std::string toString(const struct in6_addr& in6addr);
  static std::string mccToString(
      uint8_t digit1, uint8_t digit2, uint8_t digit3);
  static std::string mncToString(
      uint8_t digit1, uint8_t digit2, uint8_t digit3);
  // from /tags/ueId to .tags.ueId for MongoDB
  static void to_mongodb_path(std::string& input);
  static std::string uint8_to_hex_string(const uint8_t* v, const size_t s);
  static void hex_str_to_uint8(const char* string, uint8_t* des);
  static std::string url_decode(std::string& value);

  static bool string_to_int8(const std::string& str, uint8_t& value);
  static bool string_to_int32(const std::string& str, uint32_t& value);
  static bool string_to_int(
      const std::string& str, uint32_t& value, uint8_t base);
  static bool string_hex_to_int(const std::string& value_str, uint32_t& value);
  static uint32_t string_hex_to_int(const std::string& value_str);
  static void int_to_string_hex(
      uint32_t value, std::string& value_str, uint8_t length = 0);
  static std::string uint32_to_hex_string(uint32_t value);
  static std::string tmsi_to_string(const uint32_t tmsi);
  static void get_tmsi_from_guti(const std::string& guti, uint32_t& tmsi);
  static void get_amf_id(
      uint8_t amf_region_id, uint16_t amf_set_id, uint8_t amf_pointer,
      uint32_t& amf_id);
  static void get_amf_id(
      uint8_t amf_region_id, uint16_t amf_set_id, uint8_t amf_pointer,
      std::string& amf_id);
  static void get_amf_id(
      const std::string& amf_region_id, const std::string& amf_set_id,
      const std::string& amf_pointer, uint32_t& amf_id);
  static void get_amf_id(
      const std::string& amf_region_id, const std::string& amf_set_id,
      const std::string& amf_pointer, std::string& amf_id);
  static void convert_string_2_hex(
      const std::string& input_str, std::string& output_str);
};
}  // namespace oai::utils
#endif /* FILE_CONVERSIONS_HPP_SEEN */
