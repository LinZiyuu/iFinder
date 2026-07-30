/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PriorityLevelARP.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PriorityLevelARP::PriorityLevelARP() {
  m_PriorityLevelArp = 0;
}

//------------------------------------------------------------------------------
PriorityLevelARP::~PriorityLevelARP() {}

//------------------------------------------------------------------------------
void PriorityLevelARP::set(const long& value) {
  m_PriorityLevelArp = value;
}

//------------------------------------------------------------------------------
bool PriorityLevelARP::get(long& value) const {
  value = m_PriorityLevelArp;

  return true;
}

//------------------------------------------------------------------------------
bool PriorityLevelARP::encode(Ngap_PriorityLevelARP_t& priorityLevelArp) const {
  priorityLevelArp = m_PriorityLevelArp;

  return true;
}

//------------------------------------------------------------------------------
bool PriorityLevelARP::decode(const Ngap_PriorityLevelARP_t& priorityLevelArp) {
  m_PriorityLevelArp = priorityLevelArp;

  return true;
}
}  // namespace oai::ngap
