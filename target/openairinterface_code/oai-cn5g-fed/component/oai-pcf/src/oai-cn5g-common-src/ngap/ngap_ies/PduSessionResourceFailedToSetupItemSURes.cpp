/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceFailedToSetupItemSURes.hpp"

#include "ngap_utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceFailedToSetupItemSURes::
    PduSessionResourceFailedToSetupItemSURes() {}

//------------------------------------------------------------------------------
PduSessionResourceFailedToSetupItemSURes::
    ~PduSessionResourceFailedToSetupItemSURes() {}

//------------------------------------------------------------------------------
void PduSessionResourceFailedToSetupItemSURes::set(
    const PduSessionId& pduSessionId,
    const OCTET_STRING_t& pduSessionResource) {
  m_PduSessionId                                = pduSessionId;
  m_PduSessionResourceSetupUnsuccessfulTransfer = pduSessionResource;
}

//------------------------------------------------------------------------------
void PduSessionResourceFailedToSetupItemSURes::get(
    PduSessionId& pduSessionId, OCTET_STRING_t& pduSessionResource) const {
  pduSessionId       = m_PduSessionId;
  pduSessionResource = m_PduSessionResourceSetupUnsuccessfulTransfer;
}

//------------------------------------------------------------------------------
bool PduSessionResourceFailedToSetupItemSURes::encode(
    Ngap_PDUSessionResourceFailedToSetupItemSURes_t& pduSessionResourceItem)
    const {
  if (!m_PduSessionId.encode(pduSessionResourceItem.pDUSessionID)) return false;
  ngap_utils::octet_string_copy(
      pduSessionResourceItem.pDUSessionResourceSetupUnsuccessfulTransfer,
      m_PduSessionResourceSetupUnsuccessfulTransfer);

  return true;
}

//------------------------------------------------------------------------------
bool PduSessionResourceFailedToSetupItemSURes::decode(
    const Ngap_PDUSessionResourceFailedToSetupItemSURes_t&
        pduSessionResourceItem) {
  if (!m_PduSessionId.decode(pduSessionResourceItem.pDUSessionID)) return false;
  ngap_utils::octet_string_copy(
      m_PduSessionResourceSetupUnsuccessfulTransfer,
      pduSessionResourceItem.pDUSessionResourceSetupUnsuccessfulTransfer);
  return true;
}

}  // namespace oai::ngap
