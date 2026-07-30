/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceSetupItemCxtRes.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceSetupItemCxtRes::PduSessionResourceSetupItemCxtRes() {}

//------------------------------------------------------------------------------
PduSessionResourceSetupItemCxtRes::~PduSessionResourceSetupItemCxtRes() {}

//------------------------------------------------------------------------------
void PduSessionResourceSetupItemCxtRes::set(
    const PduSessionId& pduSessionId,
    const OCTET_STRING_t& pduSessionResourceSetupResponseTransfer) {
  m_PduSessionId = pduSessionId;
  m_PduSessionResourceSetupResponseTransfer =
      pduSessionResourceSetupResponseTransfer;
}

//------------------------------------------------------------------------------
void PduSessionResourceSetupItemCxtRes::get(
    PduSessionId& pduSessionId,
    OCTET_STRING_t& pduSessionResourceSetupResponseTransfer) const {
  pduSessionId = m_PduSessionId;
  pduSessionResourceSetupResponseTransfer =
      m_PduSessionResourceSetupResponseTransfer;
}

//------------------------------------------------------------------------------
bool PduSessionResourceSetupItemCxtRes::encode(
    Ngap_PDUSessionResourceSetupItemCxtRes_t& pduSessionResourceItem) const {
  if (!m_PduSessionId.encode(pduSessionResourceItem.pDUSessionID)) return false;
  pduSessionResourceItem.pDUSessionResourceSetupResponseTransfer =
      m_PduSessionResourceSetupResponseTransfer;

  return true;
}

//------------------------------------------------------------------------------
bool PduSessionResourceSetupItemCxtRes::decode(
    const Ngap_PDUSessionResourceSetupItemCxtRes_t& pduSessionResourceItem) {
  if (!m_PduSessionId.decode(pduSessionResourceItem.pDUSessionID)) return false;
  m_PduSessionResourceSetupResponseTransfer =
      pduSessionResourceItem.pDUSessionResourceSetupResponseTransfer;

  return true;
}

}  // namespace oai::ngap
