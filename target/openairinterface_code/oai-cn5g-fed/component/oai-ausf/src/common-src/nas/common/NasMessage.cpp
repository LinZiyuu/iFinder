/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "NasMessage.hpp"

#include "3gpp_24.501.hpp"
#include "NasHelper.hpp"
#include "common_defs.hpp"
#include "logger_base.hpp"

using namespace oai::nas;

//------------------------------------------------------------------------------
bool NasMessage::Validate(uint32_t len) const {
  uint32_t actual_length = GetLength();
  if (len < actual_length) {
    oai::logger::logger_common::nas().error(
        "Buffer length is less than the minimum length of this message "
        "(0x%x "
        "octet)",
        actual_length);
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
void NasMessage::SetMessageName(const std::string& name) {
  msg_name_ = name;
}

//------------------------------------------------------------------------------
std::string NasMessage::GetMessageName() const {
  return msg_name_;
}

//------------------------------------------------------------------------------
void NasMessage::GetMessageName(std::string& name) const {
  name = msg_name_;
}
