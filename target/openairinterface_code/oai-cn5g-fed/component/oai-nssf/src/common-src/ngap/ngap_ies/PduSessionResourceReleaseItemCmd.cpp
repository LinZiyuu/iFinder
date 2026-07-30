/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceReleaseItemCmd.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceReleaseItemCmd::PduSessionResourceReleaseItemCmd() {}

//------------------------------------------------------------------------------
PduSessionResourceReleaseItemCmd::~PduSessionResourceReleaseItemCmd() {}

//------------------------------------------------------------------------------
void PduSessionResourceReleaseItemCmd::set(
    const PduSessionId& pduSessionId,
    const OCTET_STRING_t& pduSessionResourceRelease) {
  m_PduSessionId                             = pduSessionId;
  m_PduSessionResourceReleaseCommandTransfer = pduSessionResourceRelease;
}

//------------------------------------------------------------------------------
bool PduSessionResourceReleaseItemCmd::encode(
    Ngap_PDUSessionResourceToReleaseItemRelCmd_t&
        pduSessionResourceReleaseCommandTransfer) const {
  if (!m_PduSessionId.encode(
          pduSessionResourceReleaseCommandTransfer.pDUSessionID))
    return false;
  pduSessionResourceReleaseCommandTransfer
      .pDUSessionResourceReleaseCommandTransfer =
      m_PduSessionResourceReleaseCommandTransfer;

  return true;
}

//------------------------------------------------------------------------------
bool PduSessionResourceReleaseItemCmd::decode(
    const Ngap_PDUSessionResourceToReleaseItemRelCmd_t&
        pduSessionResourceReleaseCommandTransfer) {
  if (!m_PduSessionId.decode(
          pduSessionResourceReleaseCommandTransfer.pDUSessionID))
    return false;
  m_PduSessionResourceReleaseCommandTransfer =
      pduSessionResourceReleaseCommandTransfer
          .pDUSessionResourceReleaseCommandTransfer;

  return true;
}

//------------------------------------------------------------------------------
void PduSessionResourceReleaseItemCmd::get(
    PduSessionId& pduSessionId,
    OCTET_STRING_t& pduSessionResourceRelease) const {
  pduSessionId              = m_PduSessionId;
  pduSessionResourceRelease = m_PduSessionResourceReleaseCommandTransfer;
}

}  // namespace oai::ngap
