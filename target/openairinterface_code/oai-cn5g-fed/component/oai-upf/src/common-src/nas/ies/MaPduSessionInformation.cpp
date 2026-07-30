/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "MaPduSessionInformation.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
MaPduSessionInformation::MaPduSessionInformation()
    : Type1NasIeFormatTv(kIeiMaPduSessionInformation) {}

//------------------------------------------------------------------------------
MaPduSessionInformation::MaPduSessionInformation(uint8_t value)
    : Type1NasIeFormatTv(kIeiMaPduSessionInformation) {
  SetValue(value & 0x0f);
}

//------------------------------------------------------------------------------
MaPduSessionInformation::~MaPduSessionInformation() {}

//------------------------------------------------------------------------------
void MaPduSessionInformation::Set(uint8_t value) {
  Type1NasIeFormatTv::SetValue(value & 0x0f);
}

//------------------------------------------------------------------------------
uint8_t MaPduSessionInformation::Get() const {
  return Type1NasIeFormatTv::GetValue() & 0x0f;
}
