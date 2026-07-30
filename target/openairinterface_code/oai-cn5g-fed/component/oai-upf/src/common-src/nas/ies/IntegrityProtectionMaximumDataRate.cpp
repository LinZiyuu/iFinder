/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "IntegrityProtectionMaximumDataRate.hpp"

#include "3gpp_24.501.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"
using namespace oai::nas;

//------------------------------------------------------------------------------
IntegrityProtectionMaximumDataRate::IntegrityProtectionMaximumDataRate(
    uint8_t iei)
    : Type3NasIe(iei) {
  uplink_   = 0;
  downlink_ = 0;
}

//------------------------------------------------------------------------------
IntegrityProtectionMaximumDataRate::IntegrityProtectionMaximumDataRate()
    : Type3NasIe() {
  uplink_   = 0;
  downlink_ = 0;
}

//------------------------------------------------------------------------------
IntegrityProtectionMaximumDataRate::IntegrityProtectionMaximumDataRate(
    uint8_t iei, uint8_t uplink, uint8_t downlink)
    : Type3NasIe(iei) {
  uplink_   = uplink;
  downlink_ = downlink;
}

//------------------------------------------------------------------------------
IntegrityProtectionMaximumDataRate::~IntegrityProtectionMaximumDataRate(){};

//------------------------------------------------------------------------------
uint32_t IntegrityProtectionMaximumDataRate::GetIeLength() const {
  return (
      kIntegrityProtectionMaximumDataRateMaximumLength - 1 +
      Type3NasIe::GetIeLength());
}

//------------------------------------------------------------------------------
void IntegrityProtectionMaximumDataRate::SetUplink(uint8_t uplink) {
  uplink_ = uplink;
}

//------------------------------------------------------------------------------
uint8_t IntegrityProtectionMaximumDataRate::GetUplink() const {
  return uplink_;
}

//------------------------------------------------------------------------------
void IntegrityProtectionMaximumDataRate::SetDownlink(uint8_t downlink) {
  downlink_ = downlink;
}

//------------------------------------------------------------------------------
uint8_t IntegrityProtectionMaximumDataRate::GetDownlink() const {
  return downlink_;
}

//------------------------------------------------------------------------------
void IntegrityProtectionMaximumDataRate::Set(
    uint8_t iei, uint8_t uplink, uint8_t downlink) {
  SetIei(iei);
  uplink_   = uplink;
  downlink_ = downlink;
}

//------------------------------------------------------------------------------
int IntegrityProtectionMaximumDataRate::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());

  if (len < kIntegrityProtectionMaximumDataRateMinimumLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kIntegrityProtectionMaximumDataRateMinimumLength);
    return KEncodeDecodeError;
  }
  int encoded_size = 0;

  // IEI
  encoded_size += Type3NasIe::Encode(buf + encoded_size, len);
  // Uplink
  ENCODE_U8(buf + encoded_size, uplink_, encoded_size);
  // Downlink
  ENCODE_U8(buf + encoded_size, downlink_, encoded_size);
  oai::logger::logger_common::nas().debug(
      "Encoded %s, len (%d)", GetIeName().c_str(), encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int IntegrityProtectionMaximumDataRate::Decode(
    const uint8_t* const buf, int len, bool is_iei) {
  oai::logger::logger_common::nas().debug("Decoding %s", GetIeName().c_str());

  if (len < kIntegrityProtectionMaximumDataRateMinimumLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kIntegrityProtectionMaximumDataRateMinimumLength);
    return KEncodeDecodeError;
  }

  int decoded_size = 0;
  // IEI and Length
  decoded_size += Type3NasIe::Decode(buf + decoded_size, len, is_iei);

  // Uplink
  DECODE_U8(buf + decoded_size, uplink_, decoded_size);
  // Downlink
  DECODE_U8(buf + decoded_size, downlink_, decoded_size);

  oai::logger::logger_common::nas().debug(
      "Decoded Maximum data rate per UE for user-plane integrity "
      "protection for uplink 0x%x",
      uplink_);
  oai::logger::logger_common::nas().debug(
      "Decoded Maximum data rate per UE for user-plane integrity "
      "protection for downlink 0x%x",
      downlink_);
  oai::logger::logger_common::nas().debug(
      "Decoded %s, len (%d)", GetIeName().c_str(), decoded_size);
  return decoded_size;
}
