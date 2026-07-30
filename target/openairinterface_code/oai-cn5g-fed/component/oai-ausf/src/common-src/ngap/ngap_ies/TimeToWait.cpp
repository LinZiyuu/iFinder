/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "TimeToWait.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
TimeToWait::TimeToWait() {
  m_Time = -1;
}

//------------------------------------------------------------------------------
TimeToWait::TimeToWait(e_Ngap_TimeToWait time) {
  m_Time = time;
}

//------------------------------------------------------------------------------
TimeToWait::~TimeToWait() {}

//------------------------------------------------------------------------------
void TimeToWait::set(e_Ngap_TimeToWait time) {
  m_Time = time;
}

//------------------------------------------------------------------------------
bool TimeToWait::encode(Ngap_TimeToWait_t& time) const {
  time = m_Time;
  return true;
}

//------------------------------------------------------------------------------
bool TimeToWait::decode(const Ngap_TimeToWait_t& time) {
  m_Time = time;
  return true;
}

//------------------------------------------------------------------------------
long TimeToWait::get() const {
  return m_Time;
}
}  // namespace oai::ngap
