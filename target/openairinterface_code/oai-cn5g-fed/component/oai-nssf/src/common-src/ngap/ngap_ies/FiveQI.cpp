/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "FiveQI.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
FiveQI::FiveQI() {
  m_FiveQI = 0;
}

//------------------------------------------------------------------------------
FiveQI::~FiveQI() {}

//------------------------------------------------------------------------------
void FiveQI::set(const long& value) {
  m_FiveQI = value;
}

//------------------------------------------------------------------------------
bool FiveQI::get(long& value) const {
  value = m_FiveQI;

  return true;
}

//------------------------------------------------------------------------------
bool FiveQI::encode(Ngap_FiveQI_t& value) const {
  value = m_FiveQI;

  return true;
}

//------------------------------------------------------------------------------
bool FiveQI::decode(const Ngap_FiveQI_t& value) {
  m_FiveQI = value;

  return true;
}
}  // namespace oai::ngap
