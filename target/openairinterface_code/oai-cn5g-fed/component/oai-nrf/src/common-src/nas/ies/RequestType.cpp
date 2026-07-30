/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "RequestType.hpp"

#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
RequestType::RequestType() : Type1NasIeFormatTv(kIeiRequestType) {}

//------------------------------------------------------------------------------
RequestType::RequestType(uint8_t value) : Type1NasIeFormatTv(kIeiRequestType) {
  Type1NasIeFormatTv::SetValue(value & 0x07);
}

//------------------------------------------------------------------------------
RequestType::~RequestType() {}

//------------------------------------------------------------------------------
void RequestType::SetValue(uint8_t value) {
  Type1NasIeFormatTv::SetValue(value & 0x07);
}

//------------------------------------------------------------------------------
uint8_t RequestType::GetValue() const {
  return (Type1NasIeFormatTv::GetValue() & 0x07);
}
