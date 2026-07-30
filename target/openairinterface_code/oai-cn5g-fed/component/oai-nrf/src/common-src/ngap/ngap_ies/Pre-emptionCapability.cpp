/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "Pre-emptionCapability.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
Pre_emptionCapability::Pre_emptionCapability() {
  m_Pre_emptionCapability = 0;
}

//------------------------------------------------------------------------------
Pre_emptionCapability::~Pre_emptionCapability() {}

//------------------------------------------------------------------------------
void Pre_emptionCapability::set(e_Ngap_Pre_emptionCapability value) {
  m_Pre_emptionCapability = value;
}

//------------------------------------------------------------------------------
bool Pre_emptionCapability::get(e_Ngap_Pre_emptionCapability& value) const {
  if ((m_Pre_emptionCapability == 0) || (m_Pre_emptionCapability == 1))
    value = (e_Ngap_Pre_emptionCapability) m_Pre_emptionCapability;
  else
    return false;

  return true;
}

//------------------------------------------------------------------------------
bool Pre_emptionCapability::encode(
    Ngap_Pre_emptionCapability_t& pre_emptionCapability) const {
  pre_emptionCapability = m_Pre_emptionCapability;

  return true;
}

//------------------------------------------------------------------------------
bool Pre_emptionCapability::decode(
    const Ngap_Pre_emptionCapability_t& pre_emptionCapability) {
  m_Pre_emptionCapability = pre_emptionCapability;

  return true;
}
}  // namespace oai::ngap
