/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "IntegrityProtectionIndication.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
IntegrityProtectionIndication::IntegrityProtectionIndication() {
  m_Indication = 0;
}

//------------------------------------------------------------------------------
IntegrityProtectionIndication::~IntegrityProtectionIndication() {}

//------------------------------------------------------------------------------
void IntegrityProtectionIndication::set(
    const e_Ngap_IntegrityProtectionIndication& indication) {
  m_Indication = indication;
}

//------------------------------------------------------------------------------
bool IntegrityProtectionIndication::get(long& indication) const {
  indication = m_Indication;

  return true;
}

//------------------------------------------------------------------------------
bool IntegrityProtectionIndication::encode(
    Ngap_IntegrityProtectionIndication_t& value) const {
  value = m_Indication;

  return true;
}

//------------------------------------------------------------------------------
bool IntegrityProtectionIndication::decode(
    const Ngap_IntegrityProtectionIndication_t& value) {
  m_Indication = value;

  return true;
}

}  // namespace oai::ngap
