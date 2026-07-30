/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "ConfidentialityProtectionIndication.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
ConfidentialityProtectionIndication::ConfidentialityProtectionIndication() {
  m_Indication = 0;
}

//------------------------------------------------------------------------------
void ConfidentialityProtectionIndication::set(
    const e_Ngap_ConfidentialityProtectionIndication& indication) {
  m_Indication = indication;
}

//------------------------------------------------------------------------------
bool ConfidentialityProtectionIndication::get(long& indication) const {
  indication = m_Indication;

  return true;
}

//------------------------------------------------------------------------------
bool ConfidentialityProtectionIndication::encode(
    Ngap_ConfidentialityProtectionIndication_t& indication) const {
  indication = m_Indication;

  return true;
}

//------------------------------------------------------------------------------
bool ConfidentialityProtectionIndication::decode(
    const Ngap_ConfidentialityProtectionIndication_t& indication) {
  m_Indication = indication;

  return true;
}

}  // namespace oai::ngap
