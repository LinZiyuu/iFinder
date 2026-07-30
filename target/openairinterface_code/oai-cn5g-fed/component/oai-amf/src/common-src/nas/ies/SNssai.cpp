/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "SNssai.hpp"

#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
SNssai::SNssai(uint8_t iei) : Type4NasIe(iei) {
  Clear();
  SetLengthIndicator(1);  // SST
}

//------------------------------------------------------------------------------
SNssai::SNssai(std::optional<uint8_t> iei) : Type4NasIe() {
  if (iei_.has_value()) {
    SetIei(iei.value());
  }
  Clear();
  SetLengthIndicator(1);  // SST
}

//------------------------------------------------------------------------------
void SNssai::Clear() {
  sst_              = 0;
  sd_               = SD_NO_VALUE;
  mapped_hplmn_sst_ = 0;
  mapped_hplmn_sd_  = SD_NO_VALUE;
}
//------------------------------------------------------------------------------
SNssai::SNssai(std::optional<uint8_t> iei, SNSSAI_s snssai) {
  // IEI
  if (iei_.has_value()) {
    SetIei(iei.value());
  }

  // Clear SST/SD value
  Clear();

  uint8_t actual_length = 0;
  // SST
  sst_ = snssai.sst;
  actual_length += SST_LENGTH;

  uint8_t len = snssai.length;
  len -= 1;

  // mappedHPLMN SD
  if (len == SD_LENGTH + SST_LENGTH + SD_LENGTH) {
    mapped_hplmn_sd_ = snssai.mHplmnSd;
    len -= SD_LENGTH;
    actual_length += SD_LENGTH;
  } else {
    mapped_hplmn_sd_ = SD_NO_VALUE;
  }

  // mappedHPLMN SST
  if (len == SD_LENGTH + SST_LENGTH) {
    mapped_hplmn_sst_ = snssai.mHplmnSst;
    len -= SST_LENGTH;
    actual_length += SST_LENGTH;
  } else {
    mapped_hplmn_sst_ = 0;
  }

  //  SD
  if (len == SD_LENGTH) {
    sd_ = snssai.sd;
    len -= SD_LENGTH;
    actual_length += SD_LENGTH;
  } else {
    sd_ = SD_NO_VALUE;
  }

  SetLengthIndicator(actual_length);
}

//------------------------------------------------------------------------------
SNssai::~SNssai() {}

//------------------------------------------------------------------------------
void SNssai::GetValue(SNSSAI_t& snssai) const {
  uint8_t len = {0};
  // SST
  snssai.sst = sst_;
  len += SST_LENGTH;

  // SD
  if (sd_ != SD_NO_VALUE) {
    snssai.sd = sd_;
    len += SD_LENGTH;
  } else {
    snssai.sd = SD_NO_VALUE;
  }

  // mappedHPLMN SST
  if (mapped_hplmn_sst_ != 0) {
    snssai.mHplmnSst = mapped_hplmn_sst_;
    len += SST_LENGTH;
  } else {
    snssai.mHplmnSst = 0;  // TODO
  }

  // mappedHPLMN SD
  if (mapped_hplmn_sd_ != SD_NO_VALUE) {
    snssai.mHplmnSd = mapped_hplmn_sd_;
    len += SD_LENGTH;
  } else {
    snssai.mHplmnSd = SD_NO_VALUE;
  }

  // Length
  snssai.length = len;
}

//------------------------------------------------------------------------------
void SNssai::SetSNSSAI(
    uint8_t sst, uint32_t sd, uint8_t mapped_hplmn_sst,
    uint32_t mapped_hplmn_sd) {
  uint8_t length = 0;

  // Clear SST/SD value
  Clear();

  // SST
  sst_ = sst;
  length += SST_LENGTH;

  // SD
  sd_ = sd;
  if (sd_ != SD_NO_VALUE) {
    length += SD_LENGTH;
  }

  // mappedHPLMN SST
  if (mapped_hplmn_sst_ > 0) {
    mapped_hplmn_sst_ = mapped_hplmn_sst;
    length += SST_LENGTH;
  }

  // mappedHPLMN SD
  mapped_hplmn_sd_ = mapped_hplmn_sd;
  if (mapped_hplmn_sd_ != SD_NO_VALUE) {
    length += SD_LENGTH;
  }

  SetLengthIndicator(length);
}

//------------------------------------------------------------------------------
void SNssai::SetSNSSAI(
    std::optional<int8_t> iei, uint8_t sst, uint32_t sd,
    uint8_t mapped_hplmn_sst, uint32_t mapped_hplmn_sd) {
  // IEI
  if (iei_.has_value()) {
    SetIei(iei.value());
  }

  SetSNSSAI(sst, sd, mapped_hplmn_sst, mapped_hplmn_sd);
}

//------------------------------------------------------------------------------
std::string SNssai::ToString() const {
  std::string s;
  s.append(fmt::format("SST {:#x}", sst_));

  if (sd_ != SD_NO_VALUE) {
    s.append(fmt::format(" SD {:#x}", sd_));
  }

  if (mapped_hplmn_sst_ > 0) {
    s.append(fmt::format(" M-HPLMN SST {:#x}", mapped_hplmn_sst_));
  }

  if (mapped_hplmn_sd_ != SD_NO_VALUE) {
    s.append(fmt::format(" M-HPLMN SD {:#x}", mapped_hplmn_sd_));
  }
  return s;
}

//------------------------------------------------------------------------------
int SNssai::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());

  int encoded_size = 0;
  // Validate the buffer's length and Encode IEI/Length
  int encoded_header_size = Type4NasIe::Encode(buf + encoded_size, len);
  if (encoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  encoded_size += encoded_header_size;

  oai::logger::logger_common::nas().debug(
      "Encoded header %s, len (%d)", GetIeName().c_str(), encoded_size);

  // SST
  ENCODE_U8(buf + encoded_size, sst_, encoded_size);

  // SD
  if (sd_ != SD_NO_VALUE) {
    ENCODE_U24(buf + encoded_size, sd_, encoded_size);
  }

  // mappedHPLMN SST
  if (mapped_hplmn_sst_ > 0) {
    ENCODE_U8(buf + encoded_size, mapped_hplmn_sst_, encoded_size);
  }

  // mappedHPLMN SD
  if (mapped_hplmn_sd_ != SD_NO_VALUE) {
    ENCODE_U24(buf + encoded_size, mapped_hplmn_sd_, encoded_size);
  }

  oai::logger::logger_common::nas().debug(
      "Encoded %s, len (%d)", GetIeName().c_str(), encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int SNssai::Decode(uint8_t* buf, int len, const bool is_iei) {
  if (len < kSNssaiMinimumLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kSNssaiMinimumLength);
    return KEncodeDecodeError;
  }

  uint8_t decoded_size = 0;
  uint8_t octet        = 0;
  oai::logger::logger_common::nas().debug("Decoding %s", GetIeName().c_str());

  // IEI and Length
  int decoded_header_size = Type4NasIe::Decode(buf + decoded_size, len, is_iei);
  if (decoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  decoded_size += decoded_header_size;

  // Clear SST/SD value
  Clear();

  switch (GetLengthIndicator()) {
    case 1: {
      DECODE_U8(buf + decoded_size, sst_, decoded_size);
    } break;
    case 4: {
      // SST
      DECODE_U8(buf + decoded_size, sst_, decoded_size);
      // SSD
      DECODE_U24(buf + decoded_size, sd_, decoded_size);
    } break;
    case 5: {
      // SST
      DECODE_U8(buf + decoded_size, sst_, decoded_size);
      // SD
      DECODE_U24(buf + decoded_size, sd_, decoded_size);
      // Mapped HPLMN SST
      DECODE_U8(buf + decoded_size, mapped_hplmn_sst_, decoded_size);
    } break;
    case 8: {
      // SST
      DECODE_U8(buf + decoded_size, sst_, decoded_size);
      // SD
      DECODE_U24(buf + decoded_size, sd_, decoded_size);
      // Mapped HPLMN SST
      DECODE_U8(buf + decoded_size, mapped_hplmn_sst_, decoded_size);
      // Mapped HPLMN SD
      DECODE_U24(buf + decoded_size, mapped_hplmn_sd_, decoded_size);
    } break;
  }

  oai::logger::logger_common::nas().debug(
      "Decoded S-NSSAI %s", ToString().c_str());
  oai::logger::logger_common::nas().debug(
      "Decoded %s, len (%d)", GetIeName().c_str(), decoded_size);
  return decoded_size;
}
