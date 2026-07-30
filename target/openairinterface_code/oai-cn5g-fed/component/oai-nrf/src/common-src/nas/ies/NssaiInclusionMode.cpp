/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "NssaiInclusionMode.hpp"

#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
NssaiInclusionMode::NssaiInclusionMode()
    : Type1NasIeFormatTv(kIeiNssaiInclusionMode) {}

//------------------------------------------------------------------------------
NssaiInclusionMode::NssaiInclusionMode(uint8_t value)
    : Type1NasIeFormatTv(kIeiNssaiInclusionMode) {
  SetValue(value);
}

//------------------------------------------------------------------------------
NssaiInclusionMode::~NssaiInclusionMode(){};

//------------------------------------------------------------------------------
void NssaiInclusionMode::SetValue(uint8_t value) {
  SetValue(value);
}

//------------------------------------------------------------------------------
uint8_t NssaiInclusionMode::GetValue() const {
  return GetValue();
}
