/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "ServiceType.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
ServiceType::ServiceType() : Type1NasIe(true), service_type_value_() {}

//------------------------------------------------------------------------------
ServiceType::ServiceType(uint8_t value) : Type1NasIe(true) {
  service_type_value_ = value & 0x0f;
  Type1NasIe::SetValue(service_type_value_);
}

//------------------------------------------------------------------------------
ServiceType::~ServiceType() {}

//------------------------------------------------------------------------------
void ServiceType::SetValue(uint8_t value) {
  service_type_value_ = value & 0x0f;
  Type1NasIe::SetValue(service_type_value_);
}

//------------------------------------------------------------------------------
void ServiceType::GetValue(uint8_t& value) const {
  value = service_type_value_;
}

//------------------------------------------------------------------------------
void ServiceType::SetValue() {
  Type1NasIe::SetValue(service_type_value_ & 0x0f);
}

//------------------------------------------------------------------------------
void ServiceType::GetValue() {
  service_type_value_ = value_ & 0x0f;
}
