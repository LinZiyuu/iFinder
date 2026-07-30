/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionType.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionType::PduSessionType() {
  m_PduSessionType = 0;
}

//------------------------------------------------------------------------------
PduSessionType::~PduSessionType() {}

//------------------------------------------------------------------------------
void PduSessionType::set(e_Ngap_PDUSessionType pduSessionType) {
  m_PduSessionType = pduSessionType;
}

//------------------------------------------------------------------------------
bool PduSessionType::get(long& pduSessionType) const {
  pduSessionType = m_PduSessionType;

  return true;
}

//------------------------------------------------------------------------------
bool PduSessionType::encode(Ngap_PDUSessionType_t& type) const {
  type = m_PduSessionType;

  return true;
}

//------------------------------------------------------------------------------
bool PduSessionType::decode(const Ngap_PDUSessionType_t& type) {
  m_PduSessionType = type;

  return true;
}

}  // namespace oai::ngap
