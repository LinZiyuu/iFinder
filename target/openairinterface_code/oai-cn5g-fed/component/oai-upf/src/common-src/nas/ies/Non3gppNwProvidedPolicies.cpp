/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "Non3gppNwProvidedPolicies.hpp"

#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
Non3gppNwProvidedPolicies::Non3gppNwProvidedPolicies(uint8_t value)
    : Type1NasIeFormatTv(kIeiNon3gppNwProvidedPolicies) {
  SetValue(value & 0x01);
}

//------------------------------------------------------------------------------
Non3gppNwProvidedPolicies::Non3gppNwProvidedPolicies()
    : Type1NasIeFormatTv(kIeiNon3gppNwProvidedPolicies) {}

//------------------------------------------------------------------------------
Non3gppNwProvidedPolicies::~Non3gppNwProvidedPolicies(){};

//------------------------------------------------------------------------------
void Non3gppNwProvidedPolicies::SetValue(uint8_t value) {
  SetValue(value & 0x01);
}

//------------------------------------------------------------------------------
uint8_t Non3gppNwProvidedPolicies::GetValue() const {
  return GetValue();
}
