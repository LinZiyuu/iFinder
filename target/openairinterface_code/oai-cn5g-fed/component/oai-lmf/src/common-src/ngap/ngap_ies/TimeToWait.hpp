/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _TIME_TO_WAIT_H_
#define _TIME_TO_WAIT_H_

extern "C" {
#include "Ngap_NGSetupFailure.h"
#include "Ngap_ProtocolIE-Field.h"
#include "Ngap_TimeToWait.h"
}

namespace oai::ngap {

class TimeToWait {
 public:
  TimeToWait();
  TimeToWait(e_Ngap_TimeToWait);
  virtual ~TimeToWait();

  void set(e_Ngap_TimeToWait);
  long get() const;

  bool encode(Ngap_TimeToWait_t&) const;
  bool decode(const Ngap_TimeToWait_t&);

 private:
  long m_Time;
};
}  // namespace oai::ngap

#endif
