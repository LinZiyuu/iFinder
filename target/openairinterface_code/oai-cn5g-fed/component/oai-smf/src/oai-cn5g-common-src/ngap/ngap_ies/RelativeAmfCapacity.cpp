/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "RelativeAmfCapacity.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
RelativeAmfCapacity::RelativeAmfCapacity() {
  m_AmfCapacity = 0;
}

//------------------------------------------------------------------------------
RelativeAmfCapacity::~RelativeAmfCapacity() {}

//------------------------------------------------------------------------------
void RelativeAmfCapacity::set(uint8_t amfCapacity) {
  m_AmfCapacity = amfCapacity;
}

//------------------------------------------------------------------------------
uint8_t RelativeAmfCapacity::get() const {
  return m_AmfCapacity;
}

//------------------------------------------------------------------------------
bool RelativeAmfCapacity::encode(
    Ngap_RelativeAMFCapacity_t& amfCapacity) const {
  amfCapacity = m_AmfCapacity;
  return true;
}

//------------------------------------------------------------------------------
bool RelativeAmfCapacity::decode(
    const Ngap_RelativeAMFCapacity_t& amfCapacity) {
  m_AmfCapacity = (uint8_t) amfCapacity;
  return true;
}

}  // namespace oai::ngap
