/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "ExtendedProtocolDiscriminator.hpp"

#include "3gpp_24.501.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
ExtendedProtocolDiscriminator::ExtendedProtocolDiscriminator(uint8_t epd)
    : NasIe(), epd_(epd) {}

//------------------------------------------------------------------------------
// ExtendedProtocolDiscriminator::~ExtendedProtocolDiscriminator() {}

//------------------------------------------------------------------------------
bool ExtendedProtocolDiscriminator::Validate(int len) const {
  if (len < kExtendedProtocolDiscriminatorLength) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this IE (%d "
        "octet)",
        kExtendedProtocolDiscriminatorLength);
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
uint32_t ExtendedProtocolDiscriminator::GetIeLength() const {
  return kExtendedProtocolDiscriminatorLength;
}

//------------------------------------------------------------------------------
void ExtendedProtocolDiscriminator::Set(uint8_t epd) {
  epd_ = epd;
}

//------------------------------------------------------------------------------
void ExtendedProtocolDiscriminator::Get(uint8_t& epd) const {
  epd = epd_;
}

//------------------------------------------------------------------------------
uint8_t ExtendedProtocolDiscriminator::Get() const {
  return epd_;
}

//------------------------------------------------------------------------------
int ExtendedProtocolDiscriminator::Encode(uint8_t* buf, int len) const {
  if (!Validate(len)) return KEncodeDecodeError;
  uint32_t encoded_size = 0;
  ENCODE_U8(buf, epd_, encoded_size);
  return encoded_size;
}

//------------------------------------------------------------------------------
int ExtendedProtocolDiscriminator::Decode(
    const uint8_t* const buf, int len, bool is_iei) {
  if (!Validate(len)) return KEncodeDecodeError;
  uint32_t decoded_size = 0;
  DECODE_U8(buf, epd_, decoded_size);
  return decoded_size;
}
