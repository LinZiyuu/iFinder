/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "_5gsUpdateType.hpp"

#include "3gpp_24.501.hpp"
#include "IeConst.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
_5gsUpdateType::_5gsUpdateType() : Type4NasIe(kIei5gsUpdateType) {
  eps_pnb_ciot_  = 0;
  _5gs_pnb_ciot_ = 0;
  ng_ran_        = false;
  sms_           = false;
  SetLengthIndicator(k5gsUpdateTypeContentLength);
}

//------------------------------------------------------------------------------
_5gsUpdateType::_5gsUpdateType(
    uint8_t eps_PNB_CIoT, uint8_t _5gs_PNB_CIoT, bool ng_RAN, bool sms)
    : Type4NasIe(kIei5gsUpdateType) {
  eps_pnb_ciot_  = eps_PNB_CIoT;
  _5gs_pnb_ciot_ = _5gs_PNB_CIoT;
  ng_ran_        = ng_RAN;
  sms_           = sms;
  SetLengthIndicator(k5gsUpdateTypeContentLength);
}

//------------------------------------------------------------------------------
_5gsUpdateType::~_5gsUpdateType() {}

//------------------------------------------------------------------------------
void _5gsUpdateType::SetEpsPnbCiot(uint8_t value) {
  eps_pnb_ciot_ = value & 0x03;  // 2 bits
}

//------------------------------------------------------------------------------
void _5gsUpdateType::Set5gsPnbCiot(uint8_t value) {
  _5gs_pnb_ciot_ = value & 0x03;  // 2 bits
}

//------------------------------------------------------------------------------
void _5gsUpdateType::SetNgRan(uint8_t value) {
  ng_ran_ = value & 0x01;  // 1 bit
}

//------------------------------------------------------------------------------
void _5gsUpdateType::SetSms(uint8_t value) {
  sms_ = value & 0x01;  // 1 bit
}

//------------------------------------------------------------------------------
uint8_t _5gsUpdateType::GetEpsPnbCiot() const {
  return eps_pnb_ciot_;
}

//------------------------------------------------------------------------------
uint8_t _5gsUpdateType::Get5gsPnbCiot() const {
  return _5gs_pnb_ciot_;
}

//------------------------------------------------------------------------------
bool _5gsUpdateType::GetNgRan() const {
  return ng_ran_;
}

//------------------------------------------------------------------------------
bool _5gsUpdateType::GetSms() const {
  return sms_;
}

//------------------------------------------------------------------------------
int _5gsUpdateType::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());

  int encoded_size = 0;
  // Validate the buffer's length and Encode IEI/Length
  int encoded_header_size = Type4NasIe::Encode(buf + encoded_size, len);
  if (encoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  encoded_size += encoded_header_size;

  uint8_t octet = 0;
  octet = (eps_pnb_ciot_ << 4) | (_5gs_pnb_ciot_ << 2) | (ng_ran_ << 1) | sms_;
  ENCODE_U8(buf + encoded_size, octet, encoded_size);

  oai::logger::logger_common::nas().debug(
      "Encoded %s, len (%d)", GetIeName().c_str(), encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int _5gsUpdateType::Decode(const uint8_t* const buf, int len, bool is_iei) {
  if (len < k5gsUpdateTypeLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        k5gsUpdateTypeLength);
    return KEncodeDecodeError;
  }

  uint8_t decoded_size = 0;
  uint8_t octet        = 0;
  oai::logger::logger_common::nas().debug("Decoding %s", GetIeName().c_str());

  // IEI and Length
  int decoded_header_size = Type4NasIe::Decode(buf + decoded_size, len, is_iei);
  // decoded_size += Type4NasIe::Decode(buf + decoded_size, len, is_iei);
  if (decoded_header_size == KEncodeDecodeError) return KEncodeDecodeError;
  decoded_size += decoded_header_size;

  DECODE_U8(buf + decoded_size, octet, decoded_size);

  eps_pnb_ciot_  = (octet & 0x30) >> 4;
  _5gs_pnb_ciot_ = (octet & 0x0c) >> 2;
  ng_ran_        = (octet & 0x02) >> 1;
  sms_           = (octet & 0x01);

  oai::logger::logger_common::nas().debug(
      "EPS_PNB_CIoT 0x%x, _5GS_PNB_CIoT 0x%x, NG RAN 0x%x, SMS 0x%x",
      eps_pnb_ciot_, _5gs_pnb_ciot_, ng_ran_, sms_);

  oai::logger::logger_common::nas().debug(
      "Decoded %s, len (%d)", GetIeName().c_str(), decoded_size);
  return decoded_size;
}
