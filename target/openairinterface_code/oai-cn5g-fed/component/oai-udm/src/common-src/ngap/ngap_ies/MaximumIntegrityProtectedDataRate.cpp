/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "MaximumIntegrityProtectedDataRate.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
MaximumIntegrityProtectedDataRate::MaximumIntegrityProtectedDataRate() {
  m_MaximumIntegrityProtectedDataRate = 0;
}

//------------------------------------------------------------------------------
MaximumIntegrityProtectedDataRate::MaximumIntegrityProtectedDataRate(
    const e_Ngap_MaximumIntegrityProtectedDataRate& value) {
  m_MaximumIntegrityProtectedDataRate = value;
}
//------------------------------------------------------------------------------
MaximumIntegrityProtectedDataRate::~MaximumIntegrityProtectedDataRate() {}

//------------------------------------------------------------------------------
void MaximumIntegrityProtectedDataRate::set(
    const e_Ngap_MaximumIntegrityProtectedDataRate& value) {
  m_MaximumIntegrityProtectedDataRate = value;
}

//------------------------------------------------------------------------------
bool MaximumIntegrityProtectedDataRate::get(long& value) const {
  value = m_MaximumIntegrityProtectedDataRate;

  return true;
}

//------------------------------------------------------------------------------
bool MaximumIntegrityProtectedDataRate::encode(
    Ngap_MaximumIntegrityProtectedDataRate_t& value) const {
  value = m_MaximumIntegrityProtectedDataRate;

  return true;
}

//------------------------------------------------------------------------------
bool MaximumIntegrityProtectedDataRate::decode(
    const Ngap_MaximumIntegrityProtectedDataRate_t& value) {
  m_MaximumIntegrityProtectedDataRate = value;

  return true;
}

}  // namespace oai::ngap
