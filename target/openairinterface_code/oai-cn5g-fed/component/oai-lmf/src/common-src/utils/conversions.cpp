/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "conversions.hpp"

#include <arpa/inet.h>
#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include <boost/algorithm/string.hpp>
#include <iomanip>
#include <iostream>
#include <sstream>

#include "logger_base.hpp"
#include "output_wrapper.hpp"
#include "utils.hpp"

using namespace oai::utils;

static const char hex_to_ascii_table[16] = {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
};

static const signed char ascii_to_hex_table[0x100] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0,  1,  2,  3,  4,  5,  6,  7,  8,
    9,  -1, -1, -1, -1, -1, -1, -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1};

constexpr uint8_t kUint32Length =
    8;  // 4 bytes  -8 characters representation in hex

//------------------------------------------------------------------------------
void conv::hexa_to_ascii(uint8_t* from, char* to, size_t length) {
  size_t i;

  for (i = 0; i < length; i++) {
    uint8_t upper = (from[i] & 0xf0) >> 4;
    uint8_t lower = from[i] & 0x0f;

    to[2 * i]     = hex_to_ascii_table[upper];
    to[2 * i + 1] = hex_to_ascii_table[lower];
  }
}

//------------------------------------------------------------------------------
int conv::ascii_to_hex(uint8_t* dst, const char* h) {
  const unsigned char* hex = (const unsigned char*) h;
  unsigned i               = 0;

  for (;;) {
    int high, low;

    while (*hex && isspace(*hex)) hex++;

    if (!*hex) return 1;

    high = ascii_to_hex_table[*hex++];

    if (high < 0) return 0;

    while (*hex && isspace(*hex)) hex++;

    if (!*hex) return 0;

    low = ascii_to_hex_table[*hex++];

    if (low < 0) return 0;

    dst[i++] = (high << 4) | low;
  }
}

//------------------------------------------------------------------------------
std::string conv::mccToString(uint8_t digit1, uint8_t digit2, uint8_t digit3) {
  std::string s  = {};
  uint16_t mcc16 = digit1 * 100 + digit2 * 10 + digit3;
  // s.append(std::to_string(digit1)).append(std::to_string(digit2)).append(std::to_string(digit3));
  s.append(std::to_string(mcc16));
  return s;
}

//------------------------------------------------------------------------------
std::string conv::mncToString(uint8_t digit1, uint8_t digit2, uint8_t digit3) {
  std::string s  = {};
  uint16_t mcc16 = 0;

  if (digit3 == 0x0F) {
    mcc16 = digit1 * 10 + digit2;
  } else {
    mcc16 = digit1 * 100 + digit2 * 10 + digit3;
  }
  s.append(std::to_string(mcc16));
  return s;
}

//------------------------------------------------------------------------------
struct in_addr conv::fromString(const std::string& addr4) {
  unsigned char buf[sizeof(struct in6_addr)] = {};
  auto ret = inet_pton(AF_INET, addr4.c_str(), buf);
  if (ret != 1) {
    oai::logger::logger_registry::get_logger(LOGGER_COMMON)
        .error(
            __PRETTY_FUNCTION__ + std::string{" Failed to convert "} + addr4);
  }
  struct in_addr* ia = (struct in_addr*) buf;
  return *ia;
}

//------------------------------------------------------------------------------
struct in6_addr conv::fromStringV6(const std::string& addr6) {
  unsigned char buf[sizeof(struct in6_addr)] = {};
  struct in6_addr ipv6_addr {};
  if (inet_pton(AF_INET6, addr6.c_str(), buf) == 1) {
    memcpy(&ipv6_addr, buf, sizeof(struct in6_addr));
  }
  return ipv6_addr;
}

//------------------------------------------------------------------------------
std::string conv::toString(const struct in_addr& inaddr) {
  std::string s              = {};
  char str[INET6_ADDRSTRLEN] = {};
  if (inet_ntop(AF_INET, (const void*) &inaddr, str, INET6_ADDRSTRLEN) ==
      NULL) {
    s.append("Error in_addr");
  } else {
    s.append(str);
  }
  return s;
}

//------------------------------------------------------------------------------
std::string conv::toString(const struct in6_addr& in6addr) {
  std::string s              = {};
  char str[INET6_ADDRSTRLEN] = {};
  if (inet_ntop(AF_INET6, (const void*) &in6addr, str, INET6_ADDRSTRLEN) ==
      nullptr) {
    s.append("Error in6_addr");
  } else {
    s.append(str);
  }
  return s;
}

//------------------------------------------------------------------------------
void conv::to_mongodb_path(std::string& input) {
  std::replace(input.begin(), input.end(), '/', '.');
}

//------------------------------------------------------------------------------
std::string conv::uint8_to_hex_string(const uint8_t* v, const size_t s) {
  std::stringstream ss;

  ss << std::hex << std::setfill('0');

  for (int i = 0; i < s; i++) {
    ss << std::hex << std::setw(2) << static_cast<int>(v[i]);
  }

  return ss.str();
}

//------------------------------------------------------------------------------
void conv::hex_str_to_uint8(const char* string, uint8_t* des) {
  if (string == NULL) return;

  size_t slength = strlen(string);
  if ((slength % 2) != 0)  // must be even
    return;

  size_t dlength = slength / 2;

  // des = (uint8_t*)malloc(dlength);

  memset(des, 0, dlength);

  size_t index = 0;
  while (index < slength) {
    char c    = string[index];
    int value = 0;
    if (c >= '0' && c <= '9')
      value = (c - '0');
    else if (c >= 'A' && c <= 'F')
      value = (10 + (c - 'A'));
    else if (c >= 'a' && c <= 'f')
      value = (10 + (c - 'a'));
    else
      return;

    des[(index / 2)] += value << (((index + 1) % 2) * 4);

    index++;
  }
}

//------------------------------------------------------------------------------
std::string conv::url_decode(std::string& value) {
  std::string ret;
  char ch;
  int ii;
  for (size_t i = 0; i < value.length(); i++) {
    if (int(value[i]) == 37) {
      sscanf(value.substr(i + 1, 2).c_str(), "%x", &ii);
      ch = static_cast<char>(ii);
      ret += ch;
      i = i + 2;
    } else {
      ret += value[i];
    }
  }
  return (ret);
}

//------------------------------------------------------------------------------
bool conv::string_to_int8(const std::string& str, uint8_t& value) {
  if (str.empty()) return false;
  try {
    value = (uint8_t) std::stoi(str);
  } catch (const std::exception& e) {
    oai::logger::logger_registry::get_logger(LOGGER_COMMON)
        .error("Error when converting from string to int, error: %s", e.what());
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool conv::string_to_int32(const std::string& str, uint32_t& value) {
  if (str.empty()) return false;
  try {
    value = (uint32_t) std::stoi(str);
  } catch (const std::exception& e) {
    oai::logger::logger_registry::get_logger(LOGGER_COMMON)
        .error("Error when converting from string to int, error: %s", e.what());
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool conv::string_to_int(
    const std::string& str, uint32_t& value, uint8_t base) {
  if (str.empty()) return false;
  if ((base != 10) or (base != 16)) {
    oai::logger::logger_registry::get_logger(LOGGER_COMMON)
        .warn("Only support Dec or Hex string value");
    return false;
  }
  if (base == 16) {
    if (str.size() <= 2) return false;
    if (!boost::iequals(str.substr(0, 2), "0x")) return false;
  }
  try {
    value = std::stoul(str, nullptr, base);
  } catch (const std::exception& e) {
    oai::logger::logger_registry::get_logger(LOGGER_COMMON)
        .error("Error when converting from string to int, error: %s", e.what());
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
void conv::int_to_string_hex(
    uint32_t value, std::string& value_str, uint8_t length) {
  std::stringstream stream_str;
  if (length > 0) {
    stream_str << std::setfill('0') << std::setw(length) << std::hex << value;
  } else {
    stream_str << std::hex << value;
  }

  std::string value_tmp(stream_str.str());
  value_str = value_tmp;
}

//------------------------------------------------------------------------------
bool conv::string_hex_to_int(const std::string& value_str, uint32_t& value) {
  if (value_str.empty()) return false;
  uint8_t base = 16;
  try {
    value = std::stoul(value_str, nullptr, base);
  } catch (const std::exception& e) {
    oai::logger::logger_registry::get_logger(LOGGER_COMMON)
        .error("Error when converting from string to int, error: %s", e.what());
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
uint32_t conv::string_hex_to_int(const std::string& value_str) {
  uint32_t value = {};
  if (value_str.empty()) return value;
  uint8_t base = 16;
  try {
    value = std::stoul(value_str, nullptr, base);
  } catch (const std::exception& e) {
    oai::logger::logger_registry::get_logger(LOGGER_COMMON)
        .error("Error when converting from string to int, error: %s", e.what());
    value = {};
  }
  return value;
}

//------------------------------------------------------------------------------
std::string conv::uint32_to_hex_string(uint32_t value) {
  char hex_str[kUint32Length + 1];
  sprintf(hex_str, "%X", value);
  return std::string(hex_str);
}

//------------------------------------------------------------------------------
std::string conv::tmsi_to_string(const uint32_t tmsi) {
  std::string s        = {};
  std::string tmsi_str = uint32_to_hex_string(tmsi);
  uint8_t length       = kUint32Length - tmsi_str.size();
  for (uint8_t i = 0; i < length; i++) {
    s.append("0");
  }
  s.append(std::to_string(tmsi));
  return s;
}

//------------------------------------------------------------------------------
void conv::get_tmsi_from_guti(const std::string& guti, uint32_t& tmsi) {
  // Get 8 last characters of GUTI
  uint8_t len = guti.length();
  if (len <= kUint32Length) return;
  std::string tmsi_str = guti.substr(len - kUint32Length);
  tmsi                 = string_hex_to_int(tmsi_str);
}

//------------------------------------------------------------------------------
void conv::get_amf_id(
    uint8_t amf_region_id, uint16_t amf_set_id, uint8_t amf_pointer,
    uint32_t& amf_id) {
  // AMF Region ID: 8bits
  // AMF Set ID: 10 bits
  // AMF Pointer: 6 bits
  amf_id = 0x00ffffff & ((amf_region_id << 16) | ((amf_set_id & 0x03ff) << 6) |
                         (amf_pointer & 0x3f));
}

//------------------------------------------------------------------------------
void conv::get_amf_id(
    uint8_t amf_region_id, uint16_t amf_set_id, uint8_t amf_pointer,
    std::string& amf_id) {
  // AMF Region ID: 8bits
  // AMF Set ID: 10 bits
  // AMF Pointer: 6 bits
  uint32_t amf_id_int = 0;
  get_amf_id(amf_region_id, amf_set_id, amf_pointer, amf_id_int);
  int_to_string_hex(amf_id_int, amf_id, 6);  // AMF ID: 24 bits
}

//------------------------------------------------------------------------------
void conv::get_amf_id(
    const std::string& amf_region_id, const std::string& amf_set_id,
    const std::string& amf_pointer, uint32_t& amf_id) {
  uint8_t amf_region_id_int = {};
  uint16_t amf_set_id_int   = {};
  uint8_t amf_pointer_int   = {};

  get_amf_id(
      string_hex_to_int(amf_region_id), string_hex_to_int(amf_set_id),
      string_hex_to_int(amf_pointer), amf_id);
}

//------------------------------------------------------------------------------
void conv::get_amf_id(
    const std::string& amf_region_id, const std::string& amf_set_id,
    const std::string& amf_pointer, std::string& amf_id) {
  uint32_t amf_id_int = 0;
  get_amf_id(
      string_hex_to_int(amf_region_id), string_hex_to_int(amf_set_id),
      string_hex_to_int(amf_pointer), amf_id_int);
  int_to_string_hex(amf_id_int, amf_id, 6);  // AMF ID: 24 bits
}

//------------------------------------------------------------------------------
void conv::convert_string_2_hex(
    const std::string& input_str, std::string& output_str) {
  unsigned char* data = (unsigned char*) malloc(input_str.length() + 1);
  if (!data) {
    utils::free_wrapper((void**) &data);
    return;
  }
  memset(data, 0, input_str.length() + 1);
  memcpy((void*) data, (void*) input_str.c_str(), input_str.length());
  oai::utils::output_wrapper::print_buffer(
      "amf_app", "Data input", data, input_str.length());

  char* datahex = (char*) malloc(input_str.length() * 2 + 1);
  if (!datahex) {
    utils::free_wrapper((void**) &datahex);
    utils::free_wrapper((void**) &data);
    return;
  }
  memset(datahex, 0, input_str.length() * 2 + 1);

  for (int i = 0; i < input_str.length(); i++)
    sprintf(datahex + i * 2, "%02x", data[i]);

  output_str = reinterpret_cast<char*>(datahex);
  utils::free_wrapper((void**) &datahex);
  utils::free_wrapper((void**) &data);
}
