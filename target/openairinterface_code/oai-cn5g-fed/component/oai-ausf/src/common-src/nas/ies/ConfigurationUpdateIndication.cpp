/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "ConfigurationUpdateIndication.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
ConfigurationUpdateIndication::ConfigurationUpdateIndication()
    : Type1NasIe(kIeiConfigurationUpdateIndication), red_(false), ack_(false) {
  ConfigurationUpdateIndication::SetValue();
}

//------------------------------------------------------------------------------
ConfigurationUpdateIndication::ConfigurationUpdateIndication(bool red, bool ack)
    : Type1NasIe(kIeiConfigurationUpdateIndication), red_(red), ack_(ack) {
  ConfigurationUpdateIndication::SetValue();
}

//------------------------------------------------------------------------------
ConfigurationUpdateIndication::~ConfigurationUpdateIndication() {}

//------------------------------------------------------------------------------
void ConfigurationUpdateIndication::SetRed(bool red) {
  red_ = red;
  ConfigurationUpdateIndication::SetValue();
}

//------------------------------------------------------------------------------
void ConfigurationUpdateIndication::GetRed(bool& red) const {
  red = red_;
}

//------------------------------------------------------------------------------
void ConfigurationUpdateIndication::SetAck(bool ack) {
  ack_ = ack;
  ConfigurationUpdateIndication::SetValue();
}

//------------------------------------------------------------------------------
void ConfigurationUpdateIndication::GetAck(bool& ack) const {
  ack = ack_;
}

//------------------------------------------------------------------------------
void ConfigurationUpdateIndication::SetValue() {
  value_ = red_ ? 0x02 : 0x00;
  value_ = ack_ ? (value_ | 0x01) : (value_ | 0x00);
}

//------------------------------------------------------------------------------
void ConfigurationUpdateIndication::GetValue() {
  red_ = value_ & 0x02;
  ack_ = value_ & 0x01;
}

//------------------------------------------------------------------------------
int ConfigurationUpdateIndication::Encode(uint8_t* buf, int len) const {
  return Type1NasIe::Encode(buf, len);
}

//------------------------------------------------------------------------------
int ConfigurationUpdateIndication::Decode(
    const uint8_t* const buf, int len, bool is_iei) {
  int decoded_size = Type1NasIe::Decode(buf, len, is_iei);
  if (decoded_size == KEncodeDecodeError) return KEncodeDecodeError;
  GetValue();
  return decoded_size;
}
