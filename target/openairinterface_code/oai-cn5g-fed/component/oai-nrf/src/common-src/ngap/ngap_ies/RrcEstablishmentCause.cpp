/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "RrcEstablishmentCause.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
RrcEstablishmentCause::RrcEstablishmentCause() {
  m_Cause = -1;
}

//------------------------------------------------------------------------------
RrcEstablishmentCause::~RrcEstablishmentCause() {}

//------------------------------------------------------------------------------
void RrcEstablishmentCause::set(const e_Ngap_RRCEstablishmentCause& cause) {
  m_Cause = cause;
}

//------------------------------------------------------------------------------
int RrcEstablishmentCause::get() const {
  return m_Cause;
}

//------------------------------------------------------------------------------
bool RrcEstablishmentCause::encode(Ngap_RRCEstablishmentCause_t& cause) const {
  cause = m_Cause;
  return true;
}

//------------------------------------------------------------------------------
bool RrcEstablishmentCause::decode(Ngap_RRCEstablishmentCause_t cause) {
  m_Cause = cause;

  return true;
}
}  // namespace oai::ngap
