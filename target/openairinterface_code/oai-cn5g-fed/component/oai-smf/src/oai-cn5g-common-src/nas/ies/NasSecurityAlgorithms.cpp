/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "NasSecurityAlgorithms.hpp"

#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
NasSecurityAlgorithms::NasSecurityAlgorithms()
    : Type3NasIe(),
      type_of_ciphering_algorithm_(),
      type_of_integrity_protection_algorithm_() {}

//------------------------------------------------------------------------------
NasSecurityAlgorithms::NasSecurityAlgorithms(uint8_t iei)
    : Type3NasIe(iei),
      type_of_ciphering_algorithm_(),
      type_of_integrity_protection_algorithm_() {}

//------------------------------------------------------------------------------
NasSecurityAlgorithms::~NasSecurityAlgorithms() {}

//------------------------------------------------------------------------------
NasSecurityAlgorithms::NasSecurityAlgorithms(
    uint8_t ciphering, uint8_t integrity_protection)
    : Type3NasIe() {
  type_of_ciphering_algorithm_            = ciphering & 0x0f;
  type_of_integrity_protection_algorithm_ = integrity_protection & 0x0f;
}

//------------------------------------------------------------------------------
uint32_t NasSecurityAlgorithms::GetIeLength() const {
  return (kNasSecurityAlgorithmsLength - 1 + Type3NasIe::GetIeLength());
}

//------------------------------------------------------------------------------
void NasSecurityAlgorithms::SetTypeOfCipheringAlgorithm(uint8_t value) {
  type_of_ciphering_algorithm_ = value & 0x0f;
}

//------------------------------------------------------------------------------
void NasSecurityAlgorithms::SetTypeOfIntegrityProtectionAlgorithm(
    uint8_t value) {
  type_of_integrity_protection_algorithm_ = value & 0x0f;
}

//------------------------------------------------------------------------------
uint8_t NasSecurityAlgorithms::GetTypeOfCipheringAlgorithm() const {
  return type_of_ciphering_algorithm_;
}

//------------------------------------------------------------------------------
uint8_t NasSecurityAlgorithms::GetTypeOfIntegrityProtectionAlgorithm() const {
  return type_of_integrity_protection_algorithm_;
}

//------------------------------------------------------------------------------
void NasSecurityAlgorithms::Set(
    uint8_t ciphering, uint8_t integrity_protection) {
  type_of_ciphering_algorithm_            = ciphering & 0x0f;
  type_of_integrity_protection_algorithm_ = integrity_protection & 0x0f;
}

//------------------------------------------------------------------------------
void NasSecurityAlgorithms::Get(
    uint8_t& ciphering, uint8_t& integrity_protection) const {
  ciphering            = type_of_ciphering_algorithm_;
  integrity_protection = type_of_integrity_protection_algorithm_;
}

//------------------------------------------------------------------------------
int NasSecurityAlgorithms::Encode(uint8_t* buf, int len) const {
  oai::logger::logger_common::nas().debug("Encoding %s", GetIeName().c_str());

  if (len < kNasSecurityAlgorithmsLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kNasSecurityAlgorithmsLength);
    return KEncodeDecodeError;
  }
  int encoded_size = 0;

  // IEI
  encoded_size += Type3NasIe::Encode(buf + encoded_size, len);

  uint8_t octet = 0;
  octet         = ((type_of_ciphering_algorithm_ & 0x0f) << 4) |
          (type_of_integrity_protection_algorithm_ & 0x0f);

  ENCODE_U8(buf + encoded_size, octet, encoded_size);

  oai::logger::logger_common::nas().debug(
      "Encoded %s, len (%d)", GetIeName().c_str(), encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int NasSecurityAlgorithms::Decode(
    const uint8_t* const buf, int len, bool is_iei) {
  oai::logger::logger_common::nas().debug("Decoding %s", GetIeName().c_str());

  if (len < kNasSecurityAlgorithmsLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kNasSecurityAlgorithmsLength);
    return KEncodeDecodeError;
  }

  int decoded_size = 0;

  // IEI and Length
  decoded_size += Type3NasIe::Decode(buf + decoded_size, len, is_iei);

  uint8_t octet = 0;
  DECODE_U8(buf + decoded_size, octet, decoded_size);

  type_of_ciphering_algorithm_            = (octet & 0xf0) >> 4;
  type_of_integrity_protection_algorithm_ = octet & 0x0f;

  oai::logger::logger_common::nas().debug(
      "Decoded %s, len (%d)", GetIeName().c_str(), decoded_size);
  return decoded_size;
}
