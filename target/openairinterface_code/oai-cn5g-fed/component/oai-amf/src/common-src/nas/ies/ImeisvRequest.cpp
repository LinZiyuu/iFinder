/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "ImeisvRequest.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
ImeisvRequest::ImeisvRequest() : Type1NasIeFormatTv(kIeiImeisvRequest) {}

//------------------------------------------------------------------------------
ImeisvRequest::ImeisvRequest(uint8_t value)
    : Type1NasIeFormatTv(kIeiImeisvRequest) {
  SetValue(value & 0x07);
}

//------------------------------------------------------------------------------
ImeisvRequest::~ImeisvRequest() {}

//------------------------------------------------------------------------------
void ImeisvRequest::Set(uint8_t value) {
  SetValue(value & 0x07);
}

//------------------------------------------------------------------------------
uint8_t ImeisvRequest::Get() const {
  return GetValue() & 0x07;
}
