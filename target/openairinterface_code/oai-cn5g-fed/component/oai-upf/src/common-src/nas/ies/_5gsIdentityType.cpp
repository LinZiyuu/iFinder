/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "_5gsIdentityType.hpp"

#include "logger_base.hpp"
using namespace oai::nas;

//------------------------------------------------------------------------------
_5gsIdentityType::_5gsIdentityType() : Type1NasIeFormatTv() {}

//------------------------------------------------------------------------------
_5gsIdentityType::_5gsIdentityType(uint8_t iei) : Type1NasIeFormatTv(iei) {}

//------------------------------------------------------------------------------
_5gsIdentityType::_5gsIdentityType(uint8_t iei, uint8_t value)
    : Type1NasIeFormatTv(iei) {
  Type1NasIeFormatTv::SetValue(value & 0x07);
}

//------------------------------------------------------------------------------
_5gsIdentityType::~_5gsIdentityType() {}

//------------------------------------------------------------------------------
void _5gsIdentityType::SetValue(uint8_t value) {
  Type1NasIeFormatTv::SetValue(value & 0x07);
}

//------------------------------------------------------------------------------
uint8_t _5gsIdentityType::GetValue() const {
  return Type1NasIeFormatTv::GetValue() & 0x07;
}
