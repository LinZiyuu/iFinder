/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceReleasedItemRelRes.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceReleasedItemRelRes::PduSessionResourceReleasedItemRelRes() {}

//------------------------------------------------------------------------------
PduSessionResourceReleasedItemRelRes::~PduSessionResourceReleasedItemRelRes() {}

//------------------------------------------------------------------------------
void PduSessionResourceReleasedItemRelRes::set(
    const PduSessionId& pduSessionId,
    const OCTET_STRING_t& pduSessionResourceReleaseResponseTransfer) {
  m_PduSessionId = pduSessionId;
  m_PduSessionResourceReleaseResponseTransfer =
      pduSessionResourceReleaseResponseTransfer;
}

//------------------------------------------------------------------------------
void PduSessionResourceReleasedItemRelRes::get(
    PduSessionId& pduSessionId,
    OCTET_STRING_t& pduSessionResourceReleaseResponseTransfer) const {
  pduSessionId = m_PduSessionId;
  pduSessionResourceReleaseResponseTransfer =
      m_PduSessionResourceReleaseResponseTransfer;
}

//------------------------------------------------------------------------------
bool PduSessionResourceReleasedItemRelRes::encode(
    Ngap_PDUSessionResourceReleasedItemRelRes_t& pduSessionResourceItem) const {
  if (!m_PduSessionId.encode(pduSessionResourceItem.pDUSessionID)) return false;

  pduSessionResourceItem.pDUSessionResourceReleaseResponseTransfer =
      m_PduSessionResourceReleaseResponseTransfer;

  return true;
}

//------------------------------------------------------------------------------
bool PduSessionResourceReleasedItemRelRes::decode(
    const Ngap_PDUSessionResourceReleasedItemRelRes_t& pduSessionResourceItem) {
  m_PduSessionId.set(pduSessionResourceItem.pDUSessionID);
  m_PduSessionResourceReleaseResponseTransfer =
      pduSessionResourceItem.pDUSessionResourceReleaseResponseTransfer;

  return true;
}

}  // namespace oai::ngap
