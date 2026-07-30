/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceItemHoRqd.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceItemHoRqd::PduSessionResourceItemHoRqd() {}

//------------------------------------------------------------------------------
PduSessionResourceItemHoRqd::~PduSessionResourceItemHoRqd() {}

//------------------------------------------------------------------------------
void PduSessionResourceItemHoRqd::set(
    const PduSessionId& pduSessionId,
    const OCTET_STRING_t& m_handoverRequiredTransfer) {
  m_PduSessionId             = pduSessionId;
  m_HandoverRequiredTransfer = m_handoverRequiredTransfer;
}

//------------------------------------------------------------------------------
void PduSessionResourceItemHoRqd::get(
    PduSessionId& pduSessionId,
    OCTET_STRING_t& m_handoverRequiredTransfer) const {
  pduSessionId               = m_PduSessionId;
  m_handoverRequiredTransfer = m_HandoverRequiredTransfer;
}

//------------------------------------------------------------------------------
bool PduSessionResourceItemHoRqd::encode(
    Ngap_PDUSessionResourceItemHORqd_t& pduSessionResourceItemHORqd) const {
  if (!m_PduSessionId.encode(pduSessionResourceItemHORqd.pDUSessionID))
    return false;
  pduSessionResourceItemHORqd.handoverRequiredTransfer =
      m_HandoverRequiredTransfer;

  return true;
}

//------------------------------------------------------------------------------
bool PduSessionResourceItemHoRqd::decode(
    const Ngap_PDUSessionResourceItemHORqd_t& pduSessionResourceItemHORqd) {
  if (!m_PduSessionId.decode(pduSessionResourceItemHORqd.pDUSessionID))
    return false;
  m_HandoverRequiredTransfer =
      pduSessionResourceItemHORqd.handoverRequiredTransfer;

  return true;
}

}  // namespace oai::ngap
