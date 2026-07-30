/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceFailedToSetupItemCxtRes.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceFailedToSetupItemCxtRes::
    PduSessionResourceFailedToSetupItemCxtRes() {}

//------------------------------------------------------------------------------
PduSessionResourceFailedToSetupItemCxtRes::
    ~PduSessionResourceFailedToSetupItemCxtRes() {}

//------------------------------------------------------------------------------
void PduSessionResourceFailedToSetupItemCxtRes::set(
    const PduSessionId& pduSessionId,
    const OCTET_STRING_t& pduSessionResource) {
  m_PduSessionId                                = pduSessionId;
  m_PduSessionResourceSetupUnsuccessfulTransfer = pduSessionResource;
}

//------------------------------------------------------------------------------
void PduSessionResourceFailedToSetupItemCxtRes::get(
    PduSessionId& pduSessionId, OCTET_STRING_t& pduSessionResource) const {
  pduSessionId       = m_PduSessionId;
  pduSessionResource = m_PduSessionResourceSetupUnsuccessfulTransfer;
}

//------------------------------------------------------------------------------
bool PduSessionResourceFailedToSetupItemCxtRes::encode(
    Ngap_PDUSessionResourceFailedToSetupItemCxtRes_t& pduSessionCxt) const {
  if (!m_PduSessionId.encode(pduSessionCxt.pDUSessionID)) return false;
  pduSessionCxt.pDUSessionResourceSetupUnsuccessfulTransfer =
      m_PduSessionResourceSetupUnsuccessfulTransfer;

  return true;
}

//------------------------------------------------------------------------------
bool PduSessionResourceFailedToSetupItemCxtRes::decode(
    const Ngap_PDUSessionResourceFailedToSetupItemCxtRes_t& pduSessionCxt) {
  if (!m_PduSessionId.decode(pduSessionCxt.pDUSessionID)) return false;
  m_PduSessionResourceSetupUnsuccessfulTransfer =
      pduSessionCxt.pDUSessionResourceSetupUnsuccessfulTransfer;

  return true;
}

}  // namespace oai::ngap
