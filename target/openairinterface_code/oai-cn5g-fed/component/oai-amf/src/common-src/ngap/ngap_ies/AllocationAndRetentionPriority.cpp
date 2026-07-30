/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "AllocationAndRetentionPriority.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
AllocationAndRetentionPriority::AllocationAndRetentionPriority() {}

//------------------------------------------------------------------------------
AllocationAndRetentionPriority::~AllocationAndRetentionPriority() {}

//------------------------------------------------------------------------------
void AllocationAndRetentionPriority::set(
    const PriorityLevelARP& priorityLevelArp,
    const Pre_emptionCapability& pre_emptionCapability,
    const Pre_emptionVulnerability& pre_emptionVulnerability) {
  m_PriorityLevelArp         = priorityLevelArp;
  m_Pre_emptionCapability    = pre_emptionCapability;
  m_Pre_emptionVulnerability = pre_emptionVulnerability;
}

//------------------------------------------------------------------------------
bool AllocationAndRetentionPriority::get(
    PriorityLevelARP& priorityLevelArp,
    Pre_emptionCapability& pre_emptionCapability,
    Pre_emptionVulnerability& pre_emptionVulnerability) const {
  priorityLevelArp         = m_PriorityLevelArp;
  pre_emptionCapability    = m_Pre_emptionCapability;
  pre_emptionVulnerability = m_Pre_emptionVulnerability;
  return true;
}

//------------------------------------------------------------------------------
bool AllocationAndRetentionPriority::encode(
    Ngap_AllocationAndRetentionPriority_t& allocationAndRetentionPriority)
    const {
  if (!m_PriorityLevelArp.encode(
          allocationAndRetentionPriority.priorityLevelARP))
    return false;
  if (!m_Pre_emptionCapability.encode(
          allocationAndRetentionPriority.pre_emptionCapability))
    return false;
  if (!m_Pre_emptionVulnerability.encode(
          allocationAndRetentionPriority.pre_emptionVulnerability))
    return false;

  return true;
}

//------------------------------------------------------------------------------
bool AllocationAndRetentionPriority::decode(
    const Ngap_AllocationAndRetentionPriority_t&
        allocationAndRetentionPriority) {
  if (!m_PriorityLevelArp.decode(
          allocationAndRetentionPriority.priorityLevelARP))
    return false;
  if (!m_Pre_emptionCapability.decode(
          allocationAndRetentionPriority.pre_emptionCapability))
    return false;
  if (!m_Pre_emptionVulnerability.decode(
          allocationAndRetentionPriority.pre_emptionVulnerability))
    return false;

  return true;
}
}  // namespace oai::ngap
