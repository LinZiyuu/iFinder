/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceModifyItemModRes.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceModifyItemModRes::PduSessionResourceModifyItemModRes() {}

//------------------------------------------------------------------------------
PduSessionResourceModifyItemModRes::~PduSessionResourceModifyItemModRes() {}

//------------------------------------------------------------------------------
void PduSessionResourceModifyItemModRes::set(
    const PduSessionId& pduSessionId,
    const OCTET_STRING_t& pduSessionResourceModifyResponseTransfer) {
  m_PduSessionId = pduSessionId;
  m_PduSessionResourceModifyResponseTransfer =
      pduSessionResourceModifyResponseTransfer;
}

//------------------------------------------------------------------------------
bool PduSessionResourceModifyItemModRes::encode(
    Ngap_PDUSessionResourceModifyItemModRes_t& pduSessionResourceItem) const {
  if (!m_PduSessionId.encode(pduSessionResourceItem.pDUSessionID)) return false;

  pduSessionResourceItem.pDUSessionResourceModifyResponseTransfer =
      m_PduSessionResourceModifyResponseTransfer;

  return true;
}

//------------------------------------------------------------------------------
bool PduSessionResourceModifyItemModRes::decode(
    const Ngap_PDUSessionResourceModifyItemModRes_t& pduSessionResourceItem) {
  if (!m_PduSessionId.decode(pduSessionResourceItem.pDUSessionID)) return false;

  m_PduSessionResourceModifyResponseTransfer =
      pduSessionResourceItem.pDUSessionResourceModifyResponseTransfer;

  return true;
}

//------------------------------------------------------------------------------
void PduSessionResourceModifyItemModRes::get(
    PduSessionId& pduSessionId,
    OCTET_STRING_t& pduSessionResourceModifyResponseTransfer) const {
  pduSessionId = m_PduSessionId;
  pduSessionResourceModifyResponseTransfer =
      m_PduSessionResourceModifyResponseTransfer;
}

}  // namespace oai::ngap
