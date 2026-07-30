/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "RejectedNssai.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
RejectedNssai::RejectedNssai(uint8_t iei) : Type4NasIe(iei) {
  SetLengthIndicator(kRejectedNssaiContentMinimumLength);
}

//------------------------------------------------------------------------------
RejectedNssai::~RejectedNssai() {
  rejected_nssais_.clear();
}

//------------------------------------------------------------------------------
void RejectedNssai::SetRejectedSNssais(
    const std::vector<RejectedSNssai>& nssais) {
  uint8_t length   = 0;
  rejected_nssais_ = nssais;
  for (auto n : nssais) {
    length += n.GetLength();
  }

  SetLengthIndicator(
      (length > kRejectedNssaiContentMinimumLength) ?
          length :
          kRejectedNssaiContentMinimumLength);
}

//------------------------------------------------------------------------------
void RejectedNssai::GetRejectedSNssais(
    std::vector<RejectedSNssai>& nssais) const {
  nssais = rejected_nssais_;
}
//------------------------------------------------------------------------------

int RejectedNssai::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());

  int encoded_size = 0;
  // Validate the buffer's length and Encode IEI/Length
  int encoded_header_size = Type4NasIe::Encode(buf + encoded_size, len);
  if (encoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  encoded_size += encoded_header_size;

  for (auto n : rejected_nssais_) {
    int size = n.Encode(buf + encoded_size, len - encoded_size);
    if (size != KEncodeDecodeError) {
      encoded_size += size;
    } else {
      return KEncodeDecodeError;
    }
  }

  oai::logger::logger_common::nas().debug(
      "Encoded %s, len (%d)", GetIeName().c_str(), encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int RejectedNssai::Decode(const uint8_t* const buf, int len, bool is_iei) {
  if (len < kRejectedNssaiMinimumLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kRejectedNssaiMinimumLength);
    return KEncodeDecodeError;
  }

  uint8_t decoded_size = 0;
  uint8_t octet        = 0;
  oai::logger::logger_common::nas().debug("Decoding %s", GetIeName().c_str());

  // IEI and Length
  int decoded_header_size = Type4NasIe::Decode(buf + decoded_size, len, is_iei);
  if (decoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  decoded_size += decoded_header_size;

  int ie_len = GetLengthIndicator();
  while (ie_len > 0) {
    RejectedSNssai snssai = {};
    int size = snssai.Decode(buf + decoded_size, len - decoded_size);
    if (size != KEncodeDecodeError) {
      decoded_size += size;
      ie_len -= size;
      rejected_nssais_.push_back(snssai);
    } else {
      return KEncodeDecodeError;
    }
  }

  oai::logger::logger_common::nas().debug(
      "Decoded %s, len (%d)", GetIeName().c_str(), decoded_size);
  return decoded_size;
}
