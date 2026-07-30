/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceSetupItemHoReq.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceSetupItemHoReq::PduSessionResourceSetupItemHoReq()
    : PduSessionResourceItem() {}

//------------------------------------------------------------------------------
PduSessionResourceSetupItemHoReq::~PduSessionResourceSetupItemHoReq() {}

//------------------------------------------------------------------------------
void PduSessionResourceSetupItemHoReq::set(
    const PduSessionId& pduSessionId, const SNssai& sNssai,
    const OCTET_STRING_t& handoverRequestTransfer) {
  PduSessionResourceItem::set(pduSessionId, handoverRequestTransfer);
  m_SNssai = sNssai;
}

//------------------------------------------------------------------------------
void PduSessionResourceSetupItemHoReq::get(
    PduSessionId& pduSessionId, SNssai& sNssai,
    OCTET_STRING_t& handoverRequestTransfer) const {
  PduSessionResourceItem::get(pduSessionId, handoverRequestTransfer);
  sNssai = m_SNssai;
}

//------------------------------------------------------------------------------
bool PduSessionResourceSetupItemHoReq::encode(
    Ngap_PDUSessionResourceSetupItemHOReq_t& resourceSetupItem) const {
  if (!PduSessionResourceItem::encode(
          resourceSetupItem.pDUSessionID,
          resourceSetupItem.handoverRequestTransfer))
    return false;

  if (!m_SNssai.encode(resourceSetupItem.s_NSSAI)) return false;

  return true;
}

//------------------------------------------------------------------------------
bool PduSessionResourceSetupItemHoReq::decode(
    const Ngap_PDUSessionResourceSetupItemHOReq_t& resourceSetupItem) {
  if (!PduSessionResourceItem::decode(
          resourceSetupItem.pDUSessionID,
          resourceSetupItem.handoverRequestTransfer))
    return false;

  if (!m_SNssai.decode(resourceSetupItem.s_NSSAI)) return false;

  return true;
}

}  // namespace oai::ngap
