/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceItemCxtRelReq.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceItemCxtRelReq::PduSessionResourceItemCxtRelReq() {}

//------------------------------------------------------------------------------
PduSessionResourceItemCxtRelReq::~PduSessionResourceItemCxtRelReq() {}

//------------------------------------------------------------------------------
void PduSessionResourceItemCxtRelReq::set(const PduSessionId& pduSessionId) {
  m_PduSessionId = pduSessionId;
}

//------------------------------------------------------------------------------
void PduSessionResourceItemCxtRelReq::get(PduSessionId& pduSessionId) const {
  pduSessionId = m_PduSessionId;
}

//------------------------------------------------------------------------------
PduSessionId PduSessionResourceItemCxtRelReq::get() const {
  return m_PduSessionId;
}

//------------------------------------------------------------------------------
bool PduSessionResourceItemCxtRelReq::encode(
    Ngap_PDUSessionResourceItemCxtRelReq_t& pduSessionResourceItem) const {
  if (!m_PduSessionId.encode(pduSessionResourceItem.pDUSessionID)) return false;
  return true;
}

//------------------------------------------------------------------------------
bool PduSessionResourceItemCxtRelReq::decode(
    const Ngap_PDUSessionResourceItemCxtRelReq_t& pduSessionResourceItem) {
  m_PduSessionId.set(pduSessionResourceItem.pDUSessionID);
  return true;
}

}  // namespace oai::ngap
