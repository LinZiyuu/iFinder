/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "ConfidentialityProtectionResult.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
ConfidentialityProtectionResult::ConfidentialityProtectionResult() {
  m_ConfidentialityProtectionResult = -1;
}

//------------------------------------------------------------------------------
void ConfidentialityProtectionResult::set(
    const e_Ngap_ConfidentialityProtectionResult& value) {
  m_ConfidentialityProtectionResult = value;
}

//------------------------------------------------------------------------------
bool ConfidentialityProtectionResult::get(long& value) const {
  value = m_ConfidentialityProtectionResult;

  return true;
}

//------------------------------------------------------------------------------
bool ConfidentialityProtectionResult::encode(
    Ngap_ConfidentialityProtectionResult_t& value) const {
  value = m_ConfidentialityProtectionResult;

  return true;
}

//------------------------------------------------------------------------------
bool ConfidentialityProtectionResult::decode(
    const Ngap_ConfidentialityProtectionResult_t& value) {
  m_ConfidentialityProtectionResult = value;

  return true;
}
}  // namespace oai::ngap
