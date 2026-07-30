/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "ControlPlaneServiceType.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
ControlPlaneServiceType::ControlPlaneServiceType()
    : Type1NasIe(true), service_type_value_() {}

//------------------------------------------------------------------------------
ControlPlaneServiceType::ControlPlaneServiceType(uint8_t value)
    : Type1NasIe(true) {
  service_type_value_ = value & 0x07;
  Type1NasIe::SetValue(service_type_value_);
}

//------------------------------------------------------------------------------
ControlPlaneServiceType::~ControlPlaneServiceType() {}

//------------------------------------------------------------------------------
void ControlPlaneServiceType::SetValue(uint8_t value) {
  service_type_value_ = value & 0x07;
  Type1NasIe::SetValue(service_type_value_);
}

//------------------------------------------------------------------------------
void ControlPlaneServiceType::GetValue(uint8_t& value) const {
  value = service_type_value_;
}

//------------------------------------------------------------------------------
void ControlPlaneServiceType::SetValue() {
  Type1NasIe::SetValue(service_type_value_ & 0x07);
}

//------------------------------------------------------------------------------
void ControlPlaneServiceType::GetValue() {
  service_type_value_ = value_ & 0x07;
}
