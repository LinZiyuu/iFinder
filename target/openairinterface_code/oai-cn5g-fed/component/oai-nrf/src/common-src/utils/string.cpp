/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */
#include "string.hpp"

#include <stdarg.h>

#include <algorithm>
#include <cctype>
#include <functional>
#include <locale>
#include <regex>

#include "logger_base.hpp"

// Licence : https://creativecommons.org/licenses/by-sa/4.0/legalcode
// https://stackoverflow.com/questions/216823/whats-the-best-way-to-trim-stdstring#217605

// trim from start
std::string& oai::utils::ltrim(std::string& s) {
  s.erase(
      s.begin(),
      std::find_if(
          s.begin(), s.end(), std::not1(std::ptr_fun<int, int>(std::isspace))));
  return s;
}

// trim from end
std::string& oai::utils::rtrim(std::string& s) {
  s.erase(
      std::find_if(
          s.rbegin(), s.rend(), std::not1(std::ptr_fun<int, int>(std::isspace)))
          .base(),
      s.end());
  return s;
}

// trim from both ends
std::string& oai::utils::trim(std::string& s) {
  return oai::utils::ltrim(oai::utils::rtrim(s));
}

// extract query param from given querystring
std::string query_param_tmp;
//
std::string oai::utils::get_query_param(
    std::string querystring, std::string param) {
  std::regex reList("([^=]*)=([^&]*)&?");
  query_param_tmp.clear();
  std::for_each(
      std::sregex_iterator(querystring.begin(), querystring.end(), reList),
      std::sregex_iterator(), [param](std::smatch match) {
        if (match[1] == param) {
          query_param_tmp = match[2].str().c_str();
          return;
        }
      });
  return query_param_tmp;
}

bool oai::utils::string_to_dotted(const std::string& str, std::string& dotted) {
  uint8_t offset = 0;
  uint8_t* last_size;
  uint8_t word_length = 0;

  uint8_t value[str.length() + 1];
  dotted    = {};
  last_size = &value[0];

  while (str[offset]) {
    // We replace the . by the length of the word
    if (str[offset] == '.') {
      *last_size  = word_length;
      word_length = 0;
      last_size   = &value[offset + 1];
    } else {
      word_length++;
      value[offset + 1] = str[offset];
    }

    offset++;
  }

  *last_size = word_length;
  dotted.assign((const char*) value, str.length() + 1);
  return true;
};

bool oai::utils::dotted_to_string(const std::string& dot, std::string& no_dot) {
  // uint8_t should be enough, but uint16 if length > 255.
  uint16_t offset = 0;
  bool result     = true;
  no_dot          = {};

  while (offset < dot.length()) {
    if (dot[offset] < 64) {
      if ((offset + dot[offset]) <= dot.length()) {
        if (offset) {
          no_dot.push_back('.');
        }
        no_dot.append(&dot[offset + 1], dot[offset]);
      }
      offset = offset + 1 + dot[offset];
    } else {
      // should not happen, consume bytes
      no_dot.push_back(dot[offset++]);
      result = false;
    }
  }
  return result;
};

void oai::utils::ipv4_to_bstring(struct in_addr ipv4_address, bstring str) {
  unsigned char bitstream_addr[4];
  bitstream_addr[0] = (uint8_t) ((ipv4_address.s_addr) & 0x000000ff);
  bitstream_addr[1] = (uint8_t) (((ipv4_address.s_addr) & 0x0000ff00) >> 8);
  bitstream_addr[2] = (uint8_t) (((ipv4_address.s_addr) & 0x00ff0000) >> 16);
  bitstream_addr[3] = (uint8_t) (((ipv4_address.s_addr) & 0xff000000) >> 24);

  str->slen = 4;
  memcpy(str->data, bitstream_addr, sizeof(bitstream_addr));
}

bool oai::utils::bstring_to_ipv4(bstring str, struct in_addr ipv4_address) {
  if ((str->slen != 4) or (str->data == nullptr)) return false;
  ipv4_address.s_addr = *((uint32_t*) str->data);
  return true;
}

void oai::utils::ipv6_to_bstring(struct in6_addr ipv6_address, bstring str) {
  char str_addr6[INET6_ADDRSTRLEN];
  if (inet_ntop(AF_INET6, &ipv6_address, str_addr6, sizeof(str_addr6))) {
    std::string ipv6_addr_str((char*) str_addr6, INET6_ADDRSTRLEN);
    oai::logger::logger_common::common().info(
        " Ipv6 address....: %s", ipv6_addr_str.c_str());
    unsigned char buf_in6_addr[sizeof(struct in6_addr)];
    if (inet_pton(
            AF_INET6, oai::utils::trim(ipv6_addr_str).c_str(), buf_in6_addr) ==
        1) {
      str->slen = 16;
      memcpy(str->data, buf_in6_addr, sizeof(buf_in6_addr));
    }
  }
}

bool oai::utils::bstring_to_ipv6(bstring str, struct in6_addr ipv6_address) {
  if ((str->slen != sizeof(struct in6_addr)) or (str->data == nullptr))
    return false;
  unsigned char buf_in6_addr[sizeof(struct in6_addr)];
  memcpy(ipv6_address.s6_addr, str->data, sizeof(buf_in6_addr));
  return true;
}

void oai::utils::ipv4v6_to_pdu_address_information(
    struct in_addr ipv4_address, struct in6_addr ipv6_address, bstring str) {
  unsigned char bitstream_addr[12];
  char str_addr6[INET6_ADDRSTRLEN];

  if (inet_ntop(AF_INET6, &ipv6_address, str_addr6, sizeof(str_addr6))) {
    std::string ipv6_addr_str((char*) str_addr6, INET6_ADDRSTRLEN);
    oai::logger::logger_common::common().info(
        " Ipv6 address....: %s", ipv6_addr_str.c_str());
    unsigned char buf_in6_addr[sizeof(struct in6_addr)];
    if (inet_pton(
            AF_INET6, oai::utils::trim(ipv6_addr_str).c_str(), buf_in6_addr) ==
        1) {
      for (int i = 0; i <= 7; i++)
        bitstream_addr[i] = (uint8_t) (buf_in6_addr[i]);
    }
  }

  bitstream_addr[8]  = (uint8_t) ((ipv4_address.s_addr) & 0x000000ff);
  bitstream_addr[9]  = (uint8_t) (((ipv4_address.s_addr) & 0x0000ff00) >> 8);
  bitstream_addr[10] = (uint8_t) (((ipv4_address.s_addr) & 0x00ff0000) >> 16);
  bitstream_addr[11] = (uint8_t) (((ipv4_address.s_addr) & 0xff000000) >> 24);

  str->slen = 12;
  memcpy(str->data, bitstream_addr, sizeof(bitstream_addr));
}

bool oai::utils::pdu_address_information_to_ipv4v6(
    bstring str, struct in_addr ipv4_address, struct in6_addr ipv6_address) {
  uint8_t size_str = 12;  // 4 for Ipv4 and 8 for interface identifier for the
                          // IPv6 link local address
  if ((str->slen != size_str) or (str->data == nullptr)) return false;
  // 4 octets for IPv4
  unsigned char buf_in_addr[4];
  memcpy(buf_in_addr, str->data, 4);
  ipv4_address.s_addr = *((uint32_t*) buf_in_addr);
  // 8 octets for interface identifier for the IPv6 link local address
  memcpy(ipv6_address.s6_addr, str->data + 4, 8);
  return true;
}

void oai::utils::ipv4v6_to_transport_layer_address(
    struct in_addr ipv4_address, struct in6_addr ipv6_address, bstring str) {
  unsigned char bitstream_addr[20];

  // Ipv4 address
  bitstream_addr[0] = (uint8_t) ((ipv4_address.s_addr) & 0x000000ff);
  bitstream_addr[1] = (uint8_t) (((ipv4_address.s_addr) & 0x0000ff00) >> 8);
  bitstream_addr[2] = (uint8_t) (((ipv4_address.s_addr) & 0x00ff0000) >> 16);
  bitstream_addr[3] = (uint8_t) (((ipv4_address.s_addr) & 0xff000000) >> 24);

  // Ipv6 address
  for (int i = 0; i < 16; i++)
    bitstream_addr[i + 4] = (uint8_t) (ipv6_address.s6_addr[i]);

  str->slen = 20;
  memcpy(str->data, bitstream_addr, sizeof(bitstream_addr));
}

void oai::utils::string_to_dnn(const std::string& str, bstring bstr) {
  bstr->slen = str.length();
  memcpy((void*) bstr->data, (void*) str.c_str(), str.length());
}
