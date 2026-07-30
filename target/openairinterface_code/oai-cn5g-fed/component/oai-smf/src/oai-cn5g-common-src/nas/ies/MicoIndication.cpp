/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "MicoIndication.hpp"

#include "3gpp_24.501.hpp"
#include "IeConst.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
MicoIndication::MicoIndication(bool sprti, bool raai)
    : Type1NasIeFormatTv(kIeiMicoIndication) {
  raai_  = raai;
  sprti_ = sprti;
}

//------------------------------------------------------------------------------
MicoIndication::MicoIndication() : Type1NasIeFormatTv(kIeiMicoIndication) {
  raai_  = false;
  sprti_ = false;
}

//------------------------------------------------------------------------------
MicoIndication::~MicoIndication(){};

//------------------------------------------------------------------------------
void MicoIndication::SetValue() {
  uint8_t octet = (kIeiMicoIndication << 4) | (sprti_ << 1) | raai_;
  Type1NasIeFormatTv::SetValue(octet);
}

//------------------------------------------------------------------------------
void MicoIndication::SetSprti(bool value) {
  sprti_ = value;
}

//------------------------------------------------------------------------------
bool MicoIndication::GetSprti() const {
  return sprti_;
}

//------------------------------------------------------------------------------
void MicoIndication::SetRaai(bool value) {
  raai_ = value;
}

//------------------------------------------------------------------------------
bool MicoIndication::GetRaai() const {
  return raai_;
}

//------------------------------------------------------------------------------
int MicoIndication::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());

  int ie_len = GetIeLength();

  if (len < ie_len) {  // Length of the content + IEI/Len
    oai::logger::logger_common::nas().error(
        "Size of the buffer is not enough to store this IE (IE len %d)",
        ie_len);
    return KEncodeDecodeError;
  }

  uint8_t octet    = 0;
  int encoded_size = 0;

  octet = (kIeiMicoIndication << 4) | (sprti_ << 1) | raai_;
  ENCODE_U8(buf + encoded_size, octet, encoded_size);

  oai::logger::logger_common::nas().debug(
      "Encoded %s, len (%d)", GetIeName().c_str(), encoded_size);

  return encoded_size;
}

//------------------------------------------------------------------------------
int MicoIndication::Decode(const uint8_t* const buf, int len, bool is_iei) {
  oai::logger::logger_common::nas().debug("Decoding %s", GetIeName().c_str());
  if (len < kMicoIndicationIELength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kMicoIndicationIELength);
    return KEncodeDecodeError;
  }

  uint8_t octet    = 0;
  int decoded_size = 0;

  DECODE_U8(buf + decoded_size, octet, decoded_size);
  // TODO: validate IEI

  sprti_ = octet & 0x02;
  raai_  = octet & 0x01;

  oai::logger::logger_common::nas().debug(
      "Decoded %s, len (%d)", GetIeName().c_str(), decoded_size);

  oai::logger::logger_common::nas().debug(
      "SPRTI 0x%x, RAAI 0x%x", sprti_, raai_);
  return decoded_size;
}
