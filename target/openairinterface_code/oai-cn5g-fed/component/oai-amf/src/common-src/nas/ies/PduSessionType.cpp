/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionType.hpp"

#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
PduSessionType::PduSessionType() : Type1NasIeFormatTv() {}

//------------------------------------------------------------------------------
PduSessionType::PduSessionType(uint8_t iei) : Type1NasIeFormatTv(iei) {}

//------------------------------------------------------------------------------
PduSessionType::PduSessionType(uint8_t iei, uint8_t value)
    : Type1NasIeFormatTv(iei) {
  Type1NasIeFormatTv::SetValue(value & 0x07);
}

//------------------------------------------------------------------------------
PduSessionType::~PduSessionType() {}

//------------------------------------------------------------------------------
void PduSessionType::SetValue(uint8_t value) {
  Type1NasIeFormatTv::SetValue(value & 0x07);
}

//------------------------------------------------------------------------------
uint8_t PduSessionType::GetValue() const {
  return Type1NasIeFormatTv::GetValue() & 0x07;
}
