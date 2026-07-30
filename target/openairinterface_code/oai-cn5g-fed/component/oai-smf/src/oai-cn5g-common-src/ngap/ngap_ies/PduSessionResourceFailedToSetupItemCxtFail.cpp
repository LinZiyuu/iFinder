/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceFailedToSetupItemCxtFail.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceFailedToSetupItemCxtFail::
    PduSessionResourceFailedToSetupItemCxtFail() {}

//------------------------------------------------------------------------------
PduSessionResourceFailedToSetupItemCxtFail::
    ~PduSessionResourceFailedToSetupItemCxtFail() {}

//------------------------------------------------------------------------------
void PduSessionResourceFailedToSetupItemCxtFail::set(
    const PduSessionId& pduSessionId,
    const OCTET_STRING_t& pduSessionResource) {
  m_PduSessionId                                = pduSessionId;
  m_PduSessionResourceSetupUnsuccessfulTransfer = pduSessionResource;
}

//------------------------------------------------------------------------------
void PduSessionResourceFailedToSetupItemCxtFail::get(
    PduSessionId& pduSessionId, OCTET_STRING_t& pduSessionResource) const {
  pduSessionId       = m_PduSessionId;
  pduSessionResource = m_PduSessionResourceSetupUnsuccessfulTransfer;
}

//------------------------------------------------------------------------------
bool PduSessionResourceFailedToSetupItemCxtFail::encode(
    Ngap_PDUSessionResourceFailedToSetupItemCxtFail_t& pdu_session_cxt) const {
  if (!m_PduSessionId.encode(pdu_session_cxt.pDUSessionID)) return false;
  pdu_session_cxt.pDUSessionResourceSetupUnsuccessfulTransfer =
      m_PduSessionResourceSetupUnsuccessfulTransfer;

  return true;
}

//------------------------------------------------------------------------------
bool PduSessionResourceFailedToSetupItemCxtFail::decode(
    const Ngap_PDUSessionResourceFailedToSetupItemCxtFail_t& pdu_session_cxt) {
  if (!m_PduSessionId.decode(pdu_session_cxt.pDUSessionID)) return false;
  m_PduSessionResourceSetupUnsuccessfulTransfer =
      pdu_session_cxt.pDUSessionResourceSetupUnsuccessfulTransfer;

  return true;
}

}  // namespace oai::ngap
