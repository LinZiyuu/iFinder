/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "utils.hpp"

#include "iostream"

//------------------------------------------------------------------------------
void utils::print_buffer(
    const std::string app, const std::string commit, uint8_t* buf, int len) {
  if (!app.compare("udm_ueau")) Logger::udm_ueau().info(commit.c_str());
  for (int i = 0; i < len; i++) printf("%x ", buf[i]);
  printf("\n");
}

//------------------------------------------------------------------------------
void utils::print_buffer(
    const std::string app, const std::string commit, const uint8_t* buf,
    int len) {
  if (!app.compare("udm_ueau")) std::cout << commit.c_str() << std::endl;
  Logger::udm_ueau().debug(commit.c_str());

  for (int i = 0; i < len; i++) printf("%x ", buf[i]);
  printf("\n");
}

//------------------------------------------------------------------------------
void utils::hex_str_2_byte(const char* src, unsigned char* dest, int len) {
  short i;
  unsigned char hBy, lBy;
  for (i = 0; i < len; i += 2) {
    hBy = toupper(src[i]);
    lBy = toupper(src[i + 1]);
    if (hBy > 0x39)
      hBy -= 0x37;
    else
      hBy -= 0x30;
    if (lBy > 0x39)
      lBy -= 0x37;
    else
      lBy -= 0x30;
    dest[i / 2] = (hBy << 4) | lBy;
  }
}
//------------------------------------------------------------------------------
std::vector<uint8_t> utils::hex_string_2_byte_array(
    const std::string& hexString) {
  std::vector<uint8_t> byte_array;
  if (hexString.length() % 2 == 1) {
    throw std::invalid_argument("Hex string to convert is not byte aligned");
  }
  // Loop through the hex string, two characters at a time
  for (size_t i = 0; i < hexString.length(); i += 2) {
    // Extract two characters representing a byte
    std::string byte_string = hexString.substr(i, 2);

    // Convert the byte string to a uint8_t value
    uint8_t byte_value =
        static_cast<uint8_t>(std::stoi(byte_string, nullptr, 16));

    // Add the byte to the byte array
    byte_array.push_back(byte_value);
  }
  return byte_array;
}
