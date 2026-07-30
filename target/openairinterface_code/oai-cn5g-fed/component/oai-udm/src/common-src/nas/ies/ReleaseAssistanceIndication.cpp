/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "ReleaseAssistanceIndication.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
ReleaseAssistanceIndication::ReleaseAssistanceIndication()
    : Type1NasIeFormatTv(kIeiReleaseAssistanceIndication) {}

//------------------------------------------------------------------------------
ReleaseAssistanceIndication::ReleaseAssistanceIndication(uint8_t value)
    : Type1NasIeFormatTv(kIeiReleaseAssistanceIndication) {
  SetValue(value & 0x03);
}

//------------------------------------------------------------------------------
ReleaseAssistanceIndication::~ReleaseAssistanceIndication() {}

//------------------------------------------------------------------------------
void ReleaseAssistanceIndication::Set(uint8_t value) {
  Type1NasIeFormatTv::SetValue(value & 0x03);
}

//------------------------------------------------------------------------------
uint8_t ReleaseAssistanceIndication::Get() const {
  return (Type1NasIeFormatTv::GetValue() & 0x03);
}
