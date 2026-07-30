/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _ALLOCATION_AND_RETENTION_PRIORITY_H_
#define _ALLOCATION_AND_RETENTION_PRIORITY_H_

#include "Pre-emptionCapability.hpp"
#include "Pre-emptionVulnerability.hpp"
#include "PriorityLevelARP.hpp"

extern "C" {
#include "Ngap_AllocationAndRetentionPriority.h"
}

namespace oai::ngap {

class AllocationAndRetentionPriority {
 public:
  AllocationAndRetentionPriority();
  virtual ~AllocationAndRetentionPriority();

  void set(
      const PriorityLevelARP& priorityLevelArp,
      const Pre_emptionCapability& pre_emptionCapability,
      const Pre_emptionVulnerability& pre_emptionVulnerability);
  bool get(
      PriorityLevelARP& priorityLevelArp,
      Pre_emptionCapability& pre_emptionCapability,
      Pre_emptionVulnerability& pre_emptionVulnerability) const;

  bool encode(Ngap_AllocationAndRetentionPriority_t&) const;
  bool decode(const Ngap_AllocationAndRetentionPriority_t&);

 private:
  PriorityLevelARP m_PriorityLevelArp;                  // Mandatory
  Pre_emptionCapability m_Pre_emptionCapability;        // Mandatory
  Pre_emptionVulnerability m_Pre_emptionVulnerability;  // Mandatory
};
}  // namespace oai::ngap

#endif
