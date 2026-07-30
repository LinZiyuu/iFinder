/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "_5gsDeregistrationType.hpp"

#include "3gpp_24.501.hpp"
#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
_5gsDeregistrationType::_5gsDeregistrationType() : Type1NasIeFormatTv() {
  u1.b = 0;
}

//------------------------------------------------------------------------------
_5gsDeregistrationType::_5gsDeregistrationType(uint8_t iei)
    : Type1NasIeFormatTv(iei) {
  u1.bf.iei = iei;
}

//------------------------------------------------------------------------------
_5gsDeregistrationType::_5gsDeregistrationType(uint8_t iei, uint8_t value) {
  u1.b = (iei << 4) | (value & 0x0f);
  Type1NasIeFormatTv::SetValue(value & 0x0f);
}

//------------------------------------------------------------------------------
_5gsDeregistrationType::_5gsDeregistrationType(
    _5gs_deregistration_type_t type) {
  u1.b                           = 0;
  u1.bf.switch_off               = type.switch_off;
  u1.bf.re_registration_required = type.re_registration_required;
  u1.bf.access_type              = type.access_type;
  u1.bf.iei                      = type.iei;
  if (type.iei != 0) {
    SetIei(type.iei);
  }
  Type1NasIeFormatTv::SetValue(u1.b & 0x0f);
}

//------------------------------------------------------------------------------
_5gsDeregistrationType::~_5gsDeregistrationType() {}

//------------------------------------------------------------------------------
void _5gsDeregistrationType::SetValue() {
  Type1NasIeFormatTv::SetValue(u1.b & 0x0f);
}

//------------------------------------------------------------------------------
void _5gsDeregistrationType::GetValue() {
  u1.b = Type1NasIeFormatTv::GetValue() & 0x0f;
  if (iei_.has_value()) {
    u1.b |= iei_.value() & 0xf0;
  }
}

//------------------------------------------------------------------------------
void _5gsDeregistrationType::Set(const _5gs_deregistration_type_t& type) {
  u1.b                           = 0;
  u1.bf.switch_off               = type.switch_off;
  u1.bf.re_registration_required = type.re_registration_required;
  u1.bf.access_type              = type.access_type;
  u1.bf.iei                      = type.iei;
  if (type.iei != 0) {
    SetIei(type.iei);
  }
  Type1NasIeFormatTv::SetValue(u1.b & 0x0f);
}

//------------------------------------------------------------------------------
void _5gsDeregistrationType::Get(_5gs_deregistration_type_t& type) const {
  type.switch_off               = u1.bf.switch_off;
  type.re_registration_required = u1.bf.re_registration_required;
  type.access_type              = u1.bf.access_type;
  type.iei                      = u1.bf.iei;
}

//------------------------------------------------------------------------------
void _5gsDeregistrationType::Set(uint8_t type) {
  u1.b = type;
}

//------------------------------------------------------------------------------
void _5gsDeregistrationType::Get(uint8_t& type) const {
  type = u1.b;
}
