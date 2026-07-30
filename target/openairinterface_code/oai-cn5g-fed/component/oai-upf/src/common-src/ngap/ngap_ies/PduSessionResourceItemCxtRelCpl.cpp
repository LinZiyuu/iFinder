/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceItemCxtRelCpl.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceItemCxtRelCpl::PduSessionResourceItemCxtRelCpl() {}

//------------------------------------------------------------------------------
PduSessionResourceItemCxtRelCpl::~PduSessionResourceItemCxtRelCpl() {}

//------------------------------------------------------------------------------
void PduSessionResourceItemCxtRelCpl::set(const PduSessionId& pduSessionId) {
  m_PduSessionId = pduSessionId;
}

//------------------------------------------------------------------------------
void PduSessionResourceItemCxtRelCpl::get(PduSessionId& pduSessionId) const {
  pduSessionId = m_PduSessionId;
}

//------------------------------------------------------------------------------
bool PduSessionResourceItemCxtRelCpl::encode(
    Ngap_PDUSessionResourceItemCxtRelCpl_t& pduSessionResourceItem) const {
  if (!m_PduSessionId.encode(pduSessionResourceItem.pDUSessionID)) return false;
  return true;
}

//------------------------------------------------------------------------------
bool PduSessionResourceItemCxtRelCpl::decode(
    const Ngap_PDUSessionResourceItemCxtRelCpl_t& pduSessionResourceItem) {
  m_PduSessionId.set(pduSessionResourceItem.pDUSessionID);
  return true;
}

}  // namespace oai::ngap
