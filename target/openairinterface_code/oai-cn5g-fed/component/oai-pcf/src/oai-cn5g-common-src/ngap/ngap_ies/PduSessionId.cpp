/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionId.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionId::PduSessionId() {
  m_PduSessionId = 0;
}

//------------------------------------------------------------------------------
PduSessionId::~PduSessionId() {}

//------------------------------------------------------------------------------
void PduSessionId::set(const uint8_t& id) {
  m_PduSessionId = id;
}

//------------------------------------------------------------------------------
void PduSessionId::get(uint8_t& id) const {
  id = m_PduSessionId;
}

//------------------------------------------------------------------------------
uint8_t PduSessionId::get() const {
  return m_PduSessionId;
}

//------------------------------------------------------------------------------
bool PduSessionId::encode(Ngap_PDUSessionID_t& pduSessionId) const {
  pduSessionId = m_PduSessionId;
  return true;
}

//------------------------------------------------------------------------------
bool PduSessionId::decode(Ngap_PDUSessionID_t pduSessionId) {
  m_PduSessionId = pduSessionId;
  return true;
}

}  // namespace oai::ngap
