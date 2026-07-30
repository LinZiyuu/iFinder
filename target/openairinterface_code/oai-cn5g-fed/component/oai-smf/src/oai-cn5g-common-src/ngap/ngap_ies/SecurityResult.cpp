/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "SecurityResult.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
SecurityResult::SecurityResult() {}

//------------------------------------------------------------------------------
SecurityResult::~SecurityResult() {}

//------------------------------------------------------------------------------
void SecurityResult::set(
    const IntegrityProtectionResult& integrityProtectionResult,
    const ConfidentialityProtectionResult& confidentialityProtectionResult) {
  m_IntegrityProtectionResult       = integrityProtectionResult;
  m_ConfidentialityProtectionResult = confidentialityProtectionResult;
}

//------------------------------------------------------------------------------
bool SecurityResult::get(
    IntegrityProtectionResult& integrityProtectionResult,
    ConfidentialityProtectionResult& confidentialityProtectionResult) const {
  integrityProtectionResult       = m_IntegrityProtectionResult;
  confidentialityProtectionResult = m_ConfidentialityProtectionResult;

  return true;
}

//------------------------------------------------------------------------------
bool SecurityResult::encode(Ngap_SecurityResult_t& securityResult) const {
  if (!m_IntegrityProtectionResult.encode(
          securityResult.integrityProtectionResult))
    return false;
  if (!m_ConfidentialityProtectionResult.encode(
          securityResult.confidentialityProtectionResult))
    return false;

  return true;
}

//------------------------------------------------------------------------------
bool SecurityResult::decode(const Ngap_SecurityResult_t& securityResult) {
  if (!m_IntegrityProtectionResult.decode(
          securityResult.integrityProtectionResult))
    return false;
  if (!m_ConfidentialityProtectionResult.decode(
          securityResult.confidentialityProtectionResult))
    return false;

  return true;
}
}  // namespace oai::ngap
