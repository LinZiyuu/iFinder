/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "Nssai.hpp"

#include <vector>

#include "3gpp_24.501.hpp"
#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
Nssai::Nssai(uint8_t iei) : Type4NasIe(iei) {
  SetLengthIndicator(kNssaiContentMinimumLength);
}

//------------------------------------------------------------------------------
Nssai::Nssai(uint8_t iei, const std::vector<struct SNSSAI_s>& nssai)
    : Type4NasIe(iei) {
  int length = 0;
  s_nssais_.assign(nssai.begin(), nssai.end());
  for (int i = 0; i < nssai.size(); i++) {
    length += (1 + nssai[i].length);  // 1 for length IE
  }
  SetLengthIndicator(
      (length > kNssaiContentMinimumLength) ? length :
                                              kNssaiContentMinimumLength);
}

//------------------------------------------------------------------------------
Nssai::Nssai() : Type4NasIe(), s_nssais_() {
  SetLengthIndicator(kNssaiContentMinimumLength);
}

//------------------------------------------------------------------------------
Nssai::~Nssai() {}

//------------------------------------------------------------------------------
void Nssai::GetValue(std::vector<struct SNSSAI_s>& nssai) const {
  nssai.assign(s_nssais_.begin(), s_nssais_.end());
}

//------------------------------------------------------------------------------
int Nssai::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());

  int encoded_size = 0;
  // Validate the buffer's length and Encode IEI/Length
  int encoded_header_size = Type4NasIe::Encode(buf + encoded_size, len);
  if (encoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  encoded_size += encoded_header_size;

  for (int i = 0; i < s_nssais_.size(); i++) {
    // TODO: Define encode for SNSSAI_s
    int len_s_nssai = SST_LENGTH;
    encoded_size++;  // Store the length of S-Nssai contents later

    ENCODE_U8(buf + encoded_size, s_nssais_.at(i).sst, encoded_size);

    if (s_nssais_.at(i).sd != SD_NO_VALUE) {
      len_s_nssai += SD_LENGTH;
      ENCODE_U24(buf + encoded_size, s_nssais_.at(i).sd, encoded_size);
      oai::logger::logger_common::nas().debug(
          "Encoded Nssai SD (0x%x)", s_nssais_.at(i).sd);
    }
    if (s_nssais_.at(i).length > (SST_LENGTH + SD_LENGTH)) {
      if (s_nssais_.at(i).mHplmnSst != -1) {
        len_s_nssai += SST_LENGTH;
        *(buf + encoded_size) = s_nssais_.at(i).mHplmnSst;
        encoded_size++;
      }
      if (s_nssais_.at(i).mHplmnSd != SD_NO_VALUE) {
        len_s_nssai += SD_LENGTH;
        ENCODE_U24(buf + encoded_size, s_nssais_.at(i).mHplmnSd, encoded_size);
      }
    }

    int encoded_size_tmp = 0;
    ENCODE_U8(
        buf + encoded_size - len_s_nssai - 1, len_s_nssai, encoded_size_tmp);
  }

  oai::logger::logger_common::nas().debug(
      "Encoded Nssai len (%d)", encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int Nssai::Decode(const uint8_t* const buf, int len, bool is_iei) {
  oai::logger::logger_common::nas().debug("Decoding %s", GetIeName().c_str());
  if (len < kNssaiMinimumLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kNssaiMinimumLength);
    return KEncodeDecodeError;
  }

  int decoded_size = 0;
  SNSSAI_s a       = {0, 0, 0, 0};

  // IEI and Length
  int decoded_header_size = Type4NasIe::Decode(buf + decoded_size, len, is_iei);
  if (decoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  decoded_size += decoded_header_size;

  int length_tmp = GetLengthIndicator();

  while (length_tmp) {
    // Decode length of SNSSAI
    uint8_t len_snssai = 0;
    DECODE_U8(buf + decoded_size, len_snssai, decoded_size);
    length_tmp--;

    switch (len_snssai) {
      case 1: {  // Only SST
        // SST
        DECODE_U8(buf + decoded_size, a.sst, decoded_size);
        length_tmp--;
        a.sd        = SD_NO_VALUE;
        a.mHplmnSst = 0;
        a.mHplmnSd  = 0;
      } break;
      case 4: {  // SST and SD
        // SST
        DECODE_U8(buf + decoded_size, a.sst, decoded_size);
        length_tmp--;
        // SD
        DECODE_U24(buf + decoded_size, a.sd, decoded_size);
        length_tmp -= 3;
        a.mHplmnSst = 0;
        a.mHplmnSd  = 0;
      } break;
      case 5: {  // SST, SD and HPLMN SST
        // SST
        DECODE_U8(buf + decoded_size, a.sst, decoded_size);
        length_tmp--;
        // SD
        DECODE_U24(buf + decoded_size, a.sd, decoded_size);
        length_tmp -= 3;
        // HPLMN SST
        DECODE_U8(buf + decoded_size, a.mHplmnSst, decoded_size);
        length_tmp--;
        a.mHplmnSd = SD_NO_VALUE;
      } break;
      case 8: {
        // SST
        DECODE_U8(buf + decoded_size, a.sst, decoded_size);
        length_tmp--;
        // SD
        DECODE_U24(buf + decoded_size, a.sd, decoded_size);
        length_tmp -= 3;
        // HPLMN SST
        DECODE_U8(buf + decoded_size, a.mHplmnSst, decoded_size);
        length_tmp--;
        // HPLMN SD
        DECODE_U24(buf + decoded_size, a.mHplmnSd, decoded_size);
        length_tmp -= 3;
      } break;
    }

    s_nssais_.insert(s_nssais_.end(), a);
    a = {0, 0, 0, 0};
  }

  for (int i = 0; i < s_nssais_.size(); i++) {
    oai::logger::logger_common::nas().debug(
        "Decoded Nssai %s", s_nssais_.at(i).ToString().c_str());
  }

  oai::logger::logger_common::nas().debug(
      "Decoded %s, len (%d)", GetIeName().c_str(), decoded_size);
  return decoded_size;
}
