/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceHandoverItem.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceHandoverItem::PduSessionResourceHandoverItem() {}

//------------------------------------------------------------------------------
PduSessionResourceHandoverItem::~PduSessionResourceHandoverItem() {}

//------------------------------------------------------------------------------
void PduSessionResourceHandoverItem::set(
    const PduSessionId& sessionId, const OCTET_STRING_t& commandTransfer) {
  m_PduSessionId            = sessionId;
  m_HandoverCommandTransfer = commandTransfer;
}

//------------------------------------------------------------------------------
void PduSessionResourceHandoverItem::get(
    PduSessionId& sessionId, OCTET_STRING_t& commandTransfer) const {
  sessionId       = m_PduSessionId;
  commandTransfer = m_HandoverCommandTransfer;
}

//------------------------------------------------------------------------------
bool PduSessionResourceHandoverItem::encode(
    Ngap_PDUSessionResourceHandoverItem_t& item) const {
  if (!m_PduSessionId.encode(item.pDUSessionID)) return false;
  item.handoverCommandTransfer = m_HandoverCommandTransfer;
  return true;
}

//------------------------------------------------------------------------------
bool PduSessionResourceHandoverItem::decode(
    const Ngap_PDUSessionResourceHandoverItem_t& item) {
  if (!m_PduSessionId.decode(item.pDUSessionID)) return false;
  m_HandoverCommandTransfer = item.handoverCommandTransfer;
  return true;
}
}  // namespace oai::ngap
