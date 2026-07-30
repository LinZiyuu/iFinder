/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "SscMode.hpp"

#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
SscMode::SscMode() : Type1NasIe() {}

//------------------------------------------------------------------------------
SscMode::SscMode(uint8_t iei) : Type1NasIe(iei) {}

//------------------------------------------------------------------------------
SscMode::SscMode(uint8_t iei, uint8_t value) : Type1NasIe(iei) {
  Type1NasIe::SetValue(value & 0x07);
}

//------------------------------------------------------------------------------
SscMode::~SscMode() {}

//------------------------------------------------------------------------------
void SscMode::Set(bool high_pos) {
  Type1NasIe::Set(high_pos);
}

//------------------------------------------------------------------------------
void SscMode::SetSscMode(uint8_t value) {
  ssc_mode_ = value & 0x07;
  Type1NasIe::SetValue(ssc_mode_);
}

//------------------------------------------------------------------------------
uint8_t SscMode::GetSscMode() {
  GetValue();
  return ssc_mode_;
}

//------------------------------------------------------------------------------
void SscMode::SetValue() {
  Type1NasIe::SetValue(ssc_mode_);
}

//------------------------------------------------------------------------------
void SscMode::GetValue() {
  ssc_mode_ = value_ & 0x07;  // 3 bits
}
