/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "NasKeySetIdentifier.hpp"

#include "3gpp_24.501.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
NasKeySetIdentifier::NasKeySetIdentifier()
    : Type1NasIe(), tsc_(false), key_id_() {}

//------------------------------------------------------------------------------
NasKeySetIdentifier::NasKeySetIdentifier(uint8_t iei, bool tsc, uint8_t key_id)
    : Type1NasIe(iei) {
  tsc_    = 0x01 & tsc;
  key_id_ = 0x07 & key_id;
  NasKeySetIdentifier::SetValue();
}

//------------------------------------------------------------------------------
NasKeySetIdentifier::NasKeySetIdentifier(bool tsc, uint8_t key_id)
    : Type1NasIe(false) {
  tsc_    = 0x01 & tsc;
  key_id_ = 0x07 & key_id;
  NasKeySetIdentifier::SetValue();
}

//------------------------------------------------------------------------------
NasKeySetIdentifier::~NasKeySetIdentifier(){};

//------------------------------------------------------------------------------
void NasKeySetIdentifier::Set(bool high_pos) {
  Type1NasIe::Set(high_pos);
}

//------------------------------------------------------------------------------
void NasKeySetIdentifier::SetValue() {
  if (tsc_)
    value_ = 0b1000 | (0x07 & key_id_);
  else
    value_ = 0x07 & key_id_;
}

//------------------------------------------------------------------------------
void NasKeySetIdentifier::GetValue() {
  tsc_    = (0b1000 & value_) >> 3;
  key_id_ = value_ & 0b00000111;
}

//------------------------------------------------------------------------------
void NasKeySetIdentifier::SetTypeOfSecurityContext(bool type) {
  tsc_ = type;
  SetValue();  // Update value
}

//------------------------------------------------------------------------------
void NasKeySetIdentifier::SetNasKeyIdentifier(uint8_t id) {
  key_id_ = 0x07 & id;
  SetValue();  // Update value
}

//------------------------------------------------------------------------------
bool NasKeySetIdentifier::GetTypeOfSecurityContext() const {
  return tsc_;
}

//------------------------------------------------------------------------------
uint8_t NasKeySetIdentifier::GetNasKeyIdentifier() const {
  return key_id_;
}

//------------------------------------------------------------------------------
uint8_t NasKeySetIdentifier::GetNgKsi() const {
  if (tsc_)
    return 0b1000 | (0x07 & key_id_);
  else
    return 0x07 & key_id_;
}
