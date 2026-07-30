/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "AlwaysOnPduSessionIndication.hpp"

#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
AlwaysOnPduSessionIndication::AlwaysOnPduSessionIndication()
    : Type1NasIeFormatTv(), apsi_(false) {}

//------------------------------------------------------------------------------
AlwaysOnPduSessionIndication::AlwaysOnPduSessionIndication(uint8_t iei)
    : Type1NasIeFormatTv(iei), apsi_(false) {}

//------------------------------------------------------------------------------
AlwaysOnPduSessionIndication::AlwaysOnPduSessionIndication(
    uint8_t iei, uint8_t value)
    : Type1NasIeFormatTv(iei) {
  Type1NasIeFormatTv::SetValue(0x01 & value);
  apsi_ = (0x01 & value_);
}

//------------------------------------------------------------------------------
AlwaysOnPduSessionIndication::~AlwaysOnPduSessionIndication() {}

//------------------------------------------------------------------------------
void AlwaysOnPduSessionIndication::SetValue() {
  if (apsi_) value_ = 0x01;
}

//------------------------------------------------------------------------------
void AlwaysOnPduSessionIndication::GetValue() {
  apsi_ = (0x01 & value_);
}

//------------------------------------------------------------------------------
void AlwaysOnPduSessionIndication::Set(uint8_t iei, bool apsi) {
  apsi_ = apsi;
  SetValue();
  SetIei(iei);
}

//------------------------------------------------------------------------------
void AlwaysOnPduSessionIndication::SetApsi(bool apsi) {
  apsi_ = apsi;
  SetValue();
}

//------------------------------------------------------------------------------
bool AlwaysOnPduSessionIndication::IsApsi() {
  GetValue();
  return apsi_;
}
