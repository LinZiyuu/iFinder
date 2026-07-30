/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PERIODIC_REGISTRATION_UPDATE_TIMER_H_
#define _PERIODIC_REGISTRATION_UPDATE_TIMER_H_

extern "C" {
#include "Ngap_PeriodicRegistrationUpdateTimer.h"
}

namespace oai::ngap {

class PeriodicRegistrationUpdateTimer {
 public:
  PeriodicRegistrationUpdateTimer();
  virtual ~PeriodicRegistrationUpdateTimer();

  void set(uint8_t updateTimer);
  void get(uint8_t& updateTimer) const;

  bool encode(Ngap_PeriodicRegistrationUpdateTimer_t&
                  periodicRegistrationUpdateTimer) const;
  bool decode(
      Ngap_PeriodicRegistrationUpdateTimer_t periodicRegistrationUpdateTimer);

 private:
  uint8_t m_UpdateTimer;
};

}  // namespace oai::ngap

#endif
