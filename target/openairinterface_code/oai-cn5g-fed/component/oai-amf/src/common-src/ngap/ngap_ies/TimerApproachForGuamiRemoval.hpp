/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _TIMER_APPROACH_FOR_GUAMI_REMOVAL_H_
#define _TIMER_APPROACH_FOR_GUAMI_REMOVAL_H_

extern "C" {
#include "Ngap_TimerApproachForGUAMIRemoval.h"
}

namespace oai::ngap {

class TimerApproachForGuamiRemoval {
 public:
  TimerApproachForGuamiRemoval();
  virtual ~TimerApproachForGuamiRemoval();

  void set(e_Ngap_TimerApproachForGUAMIRemoval value);
  bool get(long& value) const;

  bool encode(Ngap_TimerApproachForGUAMIRemoval_t&) const;
  bool decode(const Ngap_TimerApproachForGUAMIRemoval_t&);

 private:
  long m_TimerApproachForGuamiRemoval;
};

}  // namespace oai::ngap

#endif
