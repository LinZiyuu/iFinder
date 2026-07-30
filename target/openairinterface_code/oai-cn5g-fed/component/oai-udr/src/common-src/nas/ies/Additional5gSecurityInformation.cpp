/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "Additional5gSecurityInformation.hpp"

#include "IeConst.hpp"

#include <optional>

#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
Additional5gSecurityInformation::Additional5gSecurityInformation()
    : Type4NasIe(kIeiAdditional5gSecurityInformation) {
  rinmr_ = false;
  hdp_   = false;
  SetLengthIndicator(kAdditional5gSecurityInformationContentLength);
}

//------------------------------------------------------------------------------
Additional5gSecurityInformation::Additional5gSecurityInformation(
    bool rinmr, bool hdp)
    : Type4NasIe(kIeiAdditional5gSecurityInformation) {
  rinmr_ = rinmr;
  hdp_   = hdp;
  SetLengthIndicator(kAdditional5gSecurityInformationContentLength);
}

//------------------------------------------------------------------------------
Additional5gSecurityInformation::~Additional5gSecurityInformation() {}

//------------------------------------------------------------------------------
void Additional5gSecurityInformation::SetRinmr(bool value) {
  rinmr_ = value;
}

//------------------------------------------------------------------------------
void Additional5gSecurityInformation::SetHdp(bool value) {
  hdp_ = value;
}

//------------------------------------------------------------------------------
bool Additional5gSecurityInformation::GetRinmr() const {
  return rinmr_;
}

//------------------------------------------------------------------------------
bool Additional5gSecurityInformation::GetHdp() const {
  return hdp_;
}

//------------------------------------------------------------------------------
int Additional5gSecurityInformation::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());

  int encoded_size = 0;
  // Validate the buffer's length and Encode IEI/Length
  int encoded_header_size = Type4NasIe::Encode(buf + encoded_size, len);
  if (encoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  encoded_size += encoded_header_size;

  // Octet 3
  uint8_t octet = 0;
  if (rinmr_) octet |= 0x02;
  if (hdp_) octet |= 0x01;

  ENCODE_U8(buf + encoded_size, octet, encoded_size);

  oai::logger::logger_common::nas().debug(
      "Encoded %s, len (%d)", GetIeName().c_str(), encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int Additional5gSecurityInformation::Decode(
    const uint8_t* const buf, int len, bool is_iei) {
  if (len < kAdditional5gSecurityInformationLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kAdditional5gSecurityInformationLength);
    return KEncodeDecodeError;
  }

  uint8_t decoded_size = 0;
  oai::logger::logger_common::nas().debug("Decoding %s", GetIeName().c_str());

  // IEI and Length
  int decoded_header_size = Type4NasIe::Decode(buf + decoded_size, len, is_iei);
  if (decoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  decoded_size += decoded_header_size;

  // Octet 3
  uint8_t octet = 0;
  DECODE_U8(buf + decoded_size, octet, decoded_size);
  rinmr_ = octet & 0x02;
  hdp_   = octet & 0x01;

  oai::logger::logger_common::nas().debug(
      "Decoded %s, RINMR 0x%x, HDP 0x%x", GetIeName().c_str(), rinmr_, hdp_);

  oai::logger::logger_common::nas().debug(
      "Decoded %s, len (%d)", GetIeName().c_str(), decoded_size);
  return decoded_size;
}
