/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PriorityLevelQos.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PriorityLevelQos::PriorityLevelQos() {
  m_PriorityLevelQos = 0;
}

//------------------------------------------------------------------------------
PriorityLevelQos::~PriorityLevelQos() {}

//------------------------------------------------------------------------------
void PriorityLevelQos::set(const long& value) {
  m_PriorityLevelQos = value;
}

//------------------------------------------------------------------------------
bool PriorityLevelQos::get(long& value) const {
  value = m_PriorityLevelQos;

  return true;
}

//------------------------------------------------------------------------------
bool PriorityLevelQos::encode(Ngap_PriorityLevelQos_t& priorityLevel) const {
  priorityLevel = m_PriorityLevelQos;

  return true;
}

//------------------------------------------------------------------------------
bool PriorityLevelQos::decode(const Ngap_PriorityLevelQos_t& priorityLevel) {
  m_PriorityLevelQos = priorityLevel;

  return true;
}
}  // namespace oai::ngap
