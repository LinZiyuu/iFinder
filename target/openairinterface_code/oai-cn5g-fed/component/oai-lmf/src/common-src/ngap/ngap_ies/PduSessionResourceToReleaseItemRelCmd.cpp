/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceToReleaseItemRelCmd.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceToReleaseItemRelCmd::PduSessionResourceToReleaseItemRelCmd() {
}

//------------------------------------------------------------------------------
PduSessionResourceToReleaseItemRelCmd::
    ~PduSessionResourceToReleaseItemRelCmd() {}

//------------------------------------------------------------------------------
void PduSessionResourceToReleaseItemRelCmd::set(
    const PduSessionId& pduSessionId,
    const OCTET_STRING_t& pduSessionResourceReleaseCommandTransfer) {
  m_PduSessionId = pduSessionId;
  m_PduSessionResourceReleaseCommandTransfer =
      pduSessionResourceReleaseCommandTransfer;
}

//------------------------------------------------------------------------------
void PduSessionResourceToReleaseItemRelCmd::get(
    PduSessionId& pduSessionId,
    OCTET_STRING_t& pduSessionResourceReleaseCommandTransfer) const {
  pduSessionId = m_PduSessionId;
  pduSessionResourceReleaseCommandTransfer =
      m_PduSessionResourceReleaseCommandTransfer;
}

//------------------------------------------------------------------------------
bool PduSessionResourceToReleaseItemRelCmd::encode(
    Ngap_PDUSessionResourceToReleaseItemRelCmd_t& pduSessionResourceItem)
    const {
  if (!m_PduSessionId.encode(pduSessionResourceItem.pDUSessionID)) return false;

  pduSessionResourceItem.pDUSessionResourceReleaseCommandTransfer =
      m_PduSessionResourceReleaseCommandTransfer;

  return true;
}

//------------------------------------------------------------------------------
bool PduSessionResourceToReleaseItemRelCmd::decode(
    const Ngap_PDUSessionResourceToReleaseItemRelCmd_t&
        pduSessionResourceItem) {
  m_PduSessionResourceReleaseCommandTransfer =
      pduSessionResourceItem.pDUSessionResourceReleaseCommandTransfer;

  return true;
}

}  // namespace oai::ngap
