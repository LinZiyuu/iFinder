/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceSetupItemSURes.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceSetupItemSURes::PduSessionResourceSetupItemSURes() {}

//------------------------------------------------------------------------------
PduSessionResourceSetupItemSURes::~PduSessionResourceSetupItemSURes() {}

//------------------------------------------------------------------------------
void PduSessionResourceSetupItemSURes::set(
    const PduSessionId& pduSessionId,
    const OCTET_STRING_t& pduSessionResourceSetupResponseTransfer) {
  m_PduSessionId = pduSessionId;
  m_PduSessionResourceSetupResponseTransfer =
      pduSessionResourceSetupResponseTransfer;
}

//------------------------------------------------------------------------------
void PduSessionResourceSetupItemSURes::get(
    PduSessionId& pduSessionId,
    OCTET_STRING_t& pduSessionResourceSetupResponseTransfer) const {
  pduSessionId = m_PduSessionId;
  pduSessionResourceSetupResponseTransfer =
      m_PduSessionResourceSetupResponseTransfer;
}

//------------------------------------------------------------------------------
bool PduSessionResourceSetupItemSURes::encode(
    Ngap_PDUSessionResourceSetupItemSURes_t& pduSessionResourceItem) const {
  if (!m_PduSessionId.encode(pduSessionResourceItem.pDUSessionID)) return false;
  pduSessionResourceItem.pDUSessionResourceSetupResponseTransfer =
      m_PduSessionResourceSetupResponseTransfer;

  return true;
}

//------------------------------------------------------------------------------
bool PduSessionResourceSetupItemSURes::decode(
    const Ngap_PDUSessionResourceSetupItemSURes_t& pduSessionResourceItem) {
  if (!m_PduSessionId.decode(pduSessionResourceItem.pDUSessionID)) return false;
  m_PduSessionResourceSetupResponseTransfer =
      pduSessionResourceItem.pDUSessionResourceSetupResponseTransfer;

  return true;
}

}  // namespace oai::ngap
