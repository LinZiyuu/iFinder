/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PRIORITY_LEVEL_QOS_H_
#define _PRIORITY_LEVEL_QOS_H_

extern "C" {
#include "Ngap_PriorityLevelQos.h"
}

namespace oai::ngap {

class PriorityLevelQos {
 public:
  PriorityLevelQos();
  virtual ~PriorityLevelQos();

  void set(const long& value);
  bool get(long& value) const;

  bool encode(Ngap_PriorityLevelQos_t&) const;
  bool decode(const Ngap_PriorityLevelQos_t&);

 private:
  long m_PriorityLevelQos;
};

}  // namespace oai::ngap

#endif
