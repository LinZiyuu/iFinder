/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PeriodicRegistrationUpdateTimer.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PeriodicRegistrationUpdateTimer::PeriodicRegistrationUpdateTimer() {
  m_UpdateTimer = 0;
}

//------------------------------------------------------------------------------
PeriodicRegistrationUpdateTimer::~PeriodicRegistrationUpdateTimer() {}

//------------------------------------------------------------------------------
void PeriodicRegistrationUpdateTimer::set(uint8_t updateTimer) {
  m_UpdateTimer = updateTimer;
}

//------------------------------------------------------------------------------
bool PeriodicRegistrationUpdateTimer::encode(
    Ngap_PeriodicRegistrationUpdateTimer_t& periodicRegistrationUpdateTimer)
    const {
  periodicRegistrationUpdateTimer.size        = sizeof(uint8_t);
  periodicRegistrationUpdateTimer.bits_unused = 0;
  periodicRegistrationUpdateTimer.buf =
      (uint8_t*) calloc(1, periodicRegistrationUpdateTimer.size);
  if (!periodicRegistrationUpdateTimer.buf) return false;
  periodicRegistrationUpdateTimer.buf[0] = m_UpdateTimer;

  return true;
}

//------------------------------------------------------------------------------
bool PeriodicRegistrationUpdateTimer::decode(
    Ngap_PeriodicRegistrationUpdateTimer_t periodicRegistrationUpdateTimer) {
  if (!periodicRegistrationUpdateTimer.buf) return false;
  m_UpdateTimer = periodicRegistrationUpdateTimer.buf[0];

  return true;
}

//------------------------------------------------------------------------------
void PeriodicRegistrationUpdateTimer::get(uint8_t& updateTimer) const {
  updateTimer = m_UpdateTimer;
}

}  // namespace oai::ngap
