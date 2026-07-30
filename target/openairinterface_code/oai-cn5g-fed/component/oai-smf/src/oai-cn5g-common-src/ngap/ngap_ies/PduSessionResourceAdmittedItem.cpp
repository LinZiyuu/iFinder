/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceAdmittedItem.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceAdmittedItem::PduSessionResourceAdmittedItem() {}

//------------------------------------------------------------------------------
PduSessionResourceAdmittedItem::~PduSessionResourceAdmittedItem() {}

//------------------------------------------------------------------------------
void PduSessionResourceAdmittedItem::set(
    const PduSessionId& pduSessionID,
    const OCTET_STRING_t& handoverRequestAckTransfer) {
  m_PduSessionId               = pduSessionID;
  m_HandoverRequestAckTransfer = handoverRequestAckTransfer;
}
//------------------------------------------------------------------------------
void PduSessionResourceAdmittedItem::get(
    PduSessionId& pduSessionID,
    OCTET_STRING_t& handoverRequestAckTransfer) const {
  pduSessionID               = m_PduSessionId;
  handoverRequestAckTransfer = m_HandoverRequestAckTransfer;
}

//------------------------------------------------------------------------------
bool PduSessionResourceAdmittedItem::encode(
    Ngap_PDUSessionResourceAdmittedItem_t& pduItem) const {
  if (!m_PduSessionId.encode(pduItem.pDUSessionID)) return false;
  pduItem.handoverRequestAcknowledgeTransfer = m_HandoverRequestAckTransfer;

  return true;
}

//------------------------------------------------------------------------------
bool PduSessionResourceAdmittedItem::decode(
    const Ngap_PDUSessionResourceAdmittedItem_t& pduItem) {
  if (!m_PduSessionId.decode(pduItem.pDUSessionID)) return false;
  m_HandoverRequestAckTransfer = pduItem.handoverRequestAcknowledgeTransfer;

  return true;
}
}  // namespace oai::ngap
