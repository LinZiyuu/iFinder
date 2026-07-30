/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "LadnInformation.hpp"

#include "3gpp_24.501.hpp"
#include "IeConst.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
LadnInformation::LadnInformation() : Type6NasIe(kIeiLadnInformation) {
  SetLengthIndicator(kLadnInformationContentMinimumLength);
}

//------------------------------------------------------------------------------
LadnInformation::~LadnInformation() {}

//------------------------------------------------------------------------------
void LadnInformation::Set(const std::vector<Ladn>& value) {
  ladn_list_.assign(value.begin(), value.end());

  int length   = 0;
  uint8_t size = (value.size() > kLadnInformationMaximumSupportedLadns) ?
                     kLadnInformationMaximumSupportedLadns :
                     value.size();
  for (int i = 0; i < size; i++) {
    ladn_list_.push_back(value.at(i));
    length += value.at(i).GetLength();
  }
  SetLengthIndicator(length);
}

//------------------------------------------------------------------------------
void LadnInformation::Add(const Ladn& value) {
  if (ladn_list_.size() < kLadnInformationMaximumSupportedLadns) {
    int ie_len = GetIeLength();
    ladn_list_.push_back(value);
    ie_len += value.GetLength();
    SetLengthIndicator(ie_len);
  }
}

//------------------------------------------------------------------------------
int LadnInformation::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());

  int ie_len = GetIeLength();

  if (len < ie_len) {  // Length of the content + IEI/Len
    oai::logger::logger_common::nas().error(
        "Size of the buffer is not enough to store this IE (IE len %d)",
        ie_len);
    return KEncodeDecodeError;
  }

  int encoded_size = 0;
  /*
    // IEI and Length (later)
    int len_pos = 0;
    int encoded_header_size =
        Type6NasIe::Encode(buf + encoded_size, len, len_pos);
    if (encoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
    encoded_size += encoded_header_size;

    for (int i = 0; i < LADN.size(); i++) {
      ENCODE_U8(buf + encoded_size, blength(LADN.at(i)), encoded_size);
      encoded_size +=
          encode_bstring(LADN.at(i), (buf + encoded_size), len - encoded_size);
    }

    // Encode length
    int encoded_len_ie = 0;
    ENCODE_U16(buf + len_pos, encoded_size - GetHeaderLength(), encoded_len_ie);
  */
  oai::logger::logger_common::nas().debug(
      "Encoded %s, len (%d)", GetIeName().c_str(), encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int LadnInformation::Decode(const uint8_t* const buf, int len, bool is_iei) {
  oai::logger::logger_common::nas().debug("Decoding EPS_NAS_Message_Container");
  int decoded_size = 0;

  // IEI and Length
  uint16_t ie_len         = 0;
  int decoded_header_size = Type6NasIe::Decode(buf + decoded_size, len, is_iei);
  if (decoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  decoded_size += decoded_header_size;
  ie_len = GetLengthIndicator();
  /*
    uint8_t dnn_len = 0;
    bstring dnn     = {};
    while (ie_len) {
      DECODE_U8(buf + decoded_size, dnn_len, decoded_size);
      ie_len--;
      decode_bstring(&dnn, dnn_len, (buf + decoded_size), len - decoded_size);
      decoded_size += dnn_len;
      ie_len -= dnn_len;
      LADN.insert(LADN.end(), dnn);
    }

    for (int i = 0; i < LADN.size(); i++) {
      for (int j = 0; j < blength(LADN.at(i)); j++) {
        oai::logger::logger_common::nas().debug(
            "Decoded LadnInformation value (0x%x)",
            (uint8_t) LADN.at(i)->data[j]);
      }
    }
  */
  oai::logger::logger_common::nas().debug(
      "Decoded EPS_NAS_Message_Container (len %d)", decoded_size);
  return decoded_size;
}
