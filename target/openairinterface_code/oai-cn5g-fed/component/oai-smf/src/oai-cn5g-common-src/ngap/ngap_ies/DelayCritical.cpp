/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "DelayCritical.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
DelayCritical::DelayCritical() {
  m_DelayCritical = 0;
}

//------------------------------------------------------------------------------
DelayCritical::~DelayCritical() {}

//------------------------------------------------------------------------------
void DelayCritical::set(const e_Ngap_DelayCritical& value) {
  m_DelayCritical = value;
}

//------------------------------------------------------------------------------
bool DelayCritical::get(e_Ngap_DelayCritical& value) const {
  if ((m_DelayCritical >= 0) && (m_DelayCritical <= 1))
    value = (e_Ngap_DelayCritical) m_DelayCritical;
  else
    false;

  return true;
}

//------------------------------------------------------------------------------
bool DelayCritical::encode(Ngap_DelayCritical_t& value) const {
  value = m_DelayCritical;

  return true;
}

//------------------------------------------------------------------------------
bool DelayCritical::decode(const Ngap_DelayCritical_t& value) {
  m_DelayCritical = value;

  return true;
}
}  // namespace oai::ngap
