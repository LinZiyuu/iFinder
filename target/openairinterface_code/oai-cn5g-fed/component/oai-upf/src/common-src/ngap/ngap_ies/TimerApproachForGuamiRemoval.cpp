/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "TimerApproachForGuamiRemoval.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
TimerApproachForGuamiRemoval::TimerApproachForGuamiRemoval() {
  m_TimerApproachForGuamiRemoval = -1;
}

//------------------------------------------------------------------------------
TimerApproachForGuamiRemoval::~TimerApproachForGuamiRemoval() {}

//------------------------------------------------------------------------------
void TimerApproachForGuamiRemoval::set(
    e_Ngap_TimerApproachForGUAMIRemoval value) {
  m_TimerApproachForGuamiRemoval = value;
}

//------------------------------------------------------------------------------
bool TimerApproachForGuamiRemoval::get(long& value) const {
  value = m_TimerApproachForGuamiRemoval;

  return true;
}

//------------------------------------------------------------------------------
bool TimerApproachForGuamiRemoval::encode(
    Ngap_TimerApproachForGUAMIRemoval_t& value) const {
  value = m_TimerApproachForGuamiRemoval;

  return true;
}

//------------------------------------------------------------------------------
bool TimerApproachForGuamiRemoval::decode(
    const Ngap_TimerApproachForGUAMIRemoval_t& value) {
  m_TimerApproachForGuamiRemoval = value;

  return true;
}
}  // namespace oai::ngap
