/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "_5gsRegistrationType.hpp"

#include "3gpp_24.501.hpp"
#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
_5gsRegistrationType::_5gsRegistrationType()
    : Type1NasIeFormatTv(), follow_on_req_(false), reg_type_(0) {}

//------------------------------------------------------------------------------
_5gsRegistrationType::_5gsRegistrationType(bool follow_on_req, uint8_t type)
    : Type1NasIeFormatTv(), follow_on_req_(follow_on_req) {
  if (ValidateValue(follow_on_req, type)) reg_type_ = type;
  SetValue();
}

//------------------------------------------------------------------------------
_5gsRegistrationType::_5gsRegistrationType(
    uint8_t iei, bool follow_on_req, uint8_t type)
    : Type1NasIeFormatTv(iei) {
  follow_on_req_ = follow_on_req;
  if (ValidateValue(follow_on_req, type)) reg_type_ = type;
  SetValue();
}

//------------------------------------------------------------------------------
_5gsRegistrationType::~_5gsRegistrationType() {}

//------------------------------------------------------------------------------
void _5gsRegistrationType::SetValue() {
  if (follow_on_req_)
    value_ = 0b1000 | (0x07 & reg_type_);
  else
    value_ = 0x07 & reg_type_;
}

//------------------------------------------------------------------------------
void _5gsRegistrationType::GetValue() {
  follow_on_req_ = (0b1000 & value_) >> 3;
  reg_type_      = value_ & 0b00000111;
}

//------------------------------------------------------------------------------
bool _5gsRegistrationType::ValidateValue(bool follow_on_req, uint8_t type) {
  if (type > k5gsMobileIdentityMaxValue) return false;
  return true;
}

//------------------------------------------------------------------------------
void _5gsRegistrationType::Set(bool follow_on_req, uint8_t type, uint8_t iei) {
  follow_on_req_ = follow_on_req;
  if (ValidateValue(follow_on_req, type)) reg_type_ = type;
  SetValue();
  SetIei(iei);
}

//------------------------------------------------------------------------------
void _5gsRegistrationType::Set(bool follow_on_req, uint8_t type) {
  follow_on_req_ = follow_on_req;
  if (ValidateValue(follow_on_req, type)) reg_type_ = type;
  SetValue();
}

//------------------------------------------------------------------------------
bool _5gsRegistrationType::IsFollowOnReq() {
  GetValue();
  return follow_on_req_;
}

//------------------------------------------------------------------------------
uint8_t _5gsRegistrationType::GetRegType() {
  GetValue();
  return reg_type_;
}
