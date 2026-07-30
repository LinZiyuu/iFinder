/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "AlwaysOnPduSessionRequested.hpp"

#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
AlwaysOnPduSessionRequested::AlwaysOnPduSessionRequested()
    : Type1NasIeFormatTv() {}

//------------------------------------------------------------------------------
AlwaysOnPduSessionRequested::AlwaysOnPduSessionRequested(uint8_t iei)
    : Type1NasIeFormatTv(iei) {}

//------------------------------------------------------------------------------
AlwaysOnPduSessionRequested::AlwaysOnPduSessionRequested(
    uint8_t iei, uint8_t value)
    : Type1NasIeFormatTv(iei) {
  Type1NasIeFormatTv::SetValue(value & 0x0f);
}

//------------------------------------------------------------------------------
AlwaysOnPduSessionRequested::~AlwaysOnPduSessionRequested() {}

//------------------------------------------------------------------------------
void AlwaysOnPduSessionRequested::SetValue() {
  if (apsr_) value_ = 0x01;
}

//------------------------------------------------------------------------------
void AlwaysOnPduSessionRequested::GetValue() {
  apsr_ = (0x01 & value_);
}

//------------------------------------------------------------------------------
void AlwaysOnPduSessionRequested::Set(uint8_t iei, bool apsr) {
  apsr_ = apsr;
  SetValue();
  SetIei(iei);
}

//------------------------------------------------------------------------------
void AlwaysOnPduSessionRequested::SetApsr(bool apsr) {
  apsr_ = apsr;
  SetValue();
}

//------------------------------------------------------------------------------
bool AlwaysOnPduSessionRequested::IsApsr() {
  GetValue();
  return apsr_;
}
