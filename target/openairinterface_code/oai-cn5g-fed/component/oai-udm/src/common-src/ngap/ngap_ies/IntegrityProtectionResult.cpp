/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "IntegrityProtectionResult.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
IntegrityProtectionResult::IntegrityProtectionResult() {
  m_Result = -1;
}

//------------------------------------------------------------------------------
IntegrityProtectionResult::~IntegrityProtectionResult() {}

//------------------------------------------------------------------------------
void IntegrityProtectionResult::set(
    const e_Ngap_IntegrityProtectionResult& value) {
  m_Result = value;
}

//------------------------------------------------------------------------------
bool IntegrityProtectionResult::get(long& value) const {
  value = m_Result;

  return true;
}

//------------------------------------------------------------------------------
bool IntegrityProtectionResult::encode(
    Ngap_IntegrityProtectionResult_t& value) const {
  value = m_Result;

  return true;
}

//------------------------------------------------------------------------------
bool IntegrityProtectionResult::decode(
    const Ngap_IntegrityProtectionResult_t& value) {
  m_Result = value;

  return true;
}
}  // namespace oai::ngap
