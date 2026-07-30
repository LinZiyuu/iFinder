/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "AllowedSscMode.hpp"

#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
AllowedSscMode::AllowedSscMode() : Type1NasIeFormatTv(kIeiAllowedSscMode) {}

//------------------------------------------------------------------------------
AllowedSscMode::AllowedSscMode(uint8_t iei) : Type1NasIeFormatTv(iei) {}

//------------------------------------------------------------------------------
AllowedSscMode::AllowedSscMode(uint8_t iei, uint8_t value)
    : Type1NasIeFormatTv(iei) {
  Type1NasIeFormatTv::SetValue(value & 0x07);
}

//------------------------------------------------------------------------------
AllowedSscMode::~AllowedSscMode() {}

//------------------------------------------------------------------------------
void AllowedSscMode::SetValue(uint8_t value) {
  Type1NasIeFormatTv::SetValue(value & 0x07);
}

//------------------------------------------------------------------------------
uint8_t AllowedSscMode::GetValue() const {
  return Type1NasIeFormatTv::GetValue() & 0x07;
}

//------------------------------------------------------------------------------
bool AllowedSscMode::IsSscMode1Allowed() const {
  return (value_ & 0x01);
}

//------------------------------------------------------------------------------
bool AllowedSscMode::IsSscMode2Allowed() const {
  return (value_ & 0x02);
}

//------------------------------------------------------------------------------
bool AllowedSscMode::IsSscMode3Allowed() const {
  return (value_ & 0x04);
}
