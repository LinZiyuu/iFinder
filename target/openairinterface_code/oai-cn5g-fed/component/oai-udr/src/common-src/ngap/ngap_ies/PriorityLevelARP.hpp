/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PRIORITY_LEVEL_ARP_H_
#define _PRIORITY_LEVEL_ARP_H_

extern "C" {
#include "Ngap_PriorityLevelARP.h"
}

namespace oai::ngap {

class PriorityLevelARP {
 public:
  PriorityLevelARP();
  virtual ~PriorityLevelARP();

  void set(const long& value);
  bool get(long& value) const;

  bool encode(Ngap_PriorityLevelARP_t&) const;
  bool decode(const Ngap_PriorityLevelARP_t&);

 private:
  long m_PriorityLevelArp;
};

}  // namespace oai::ngap

#endif
