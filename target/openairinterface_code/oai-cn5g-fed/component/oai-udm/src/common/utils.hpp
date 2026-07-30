/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PRINT_BUFFER_H
#define _PRINT_BUFFER_H

#include <string>
#include <vector>

#include "logger.hpp"

class utils {
 public:
  static void print_buffer(
      const std::string app, const std::string commit, uint8_t* buf, int len);
  static void print_buffer(
      const std::string app, const std::string commit, const uint8_t* buf,
      int len);
  static void hex_str_2_byte(const char* src, unsigned char* dest, int len);
  static std::vector<uint8_t> hex_string_2_byte_array(
      const std::string& hexString);
};

#endif
