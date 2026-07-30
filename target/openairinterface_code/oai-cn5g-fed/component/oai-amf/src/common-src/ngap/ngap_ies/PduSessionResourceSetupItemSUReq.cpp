/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceSetupItemSUReq.hpp"

#include "utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceSetupItemSUReq::PduSessionResourceSetupItemSUReq() {
  m_NasPdu = std::nullopt;
}

//------------------------------------------------------------------------------
PduSessionResourceSetupItemSUReq::~PduSessionResourceSetupItemSUReq() {}

//------------------------------------------------------------------------------
void PduSessionResourceSetupItemSUReq::set(
    const PduSessionId& pduSessionId, std::optional<NasPdu>& nasPdu,
    const SNssai& sNssai,
    const OCTET_STRING_t& pduSessionResourceSetupRequestTransfer) {
  m_PduSessionId = pduSessionId;
  m_NasPdu       = nasPdu;
  m_SNssai       = sNssai;
  m_PduSessionResourceSetupRequestTransfer =
      pduSessionResourceSetupRequestTransfer;
}

//------------------------------------------------------------------------------
void PduSessionResourceSetupItemSUReq::get(
    PduSessionId& pduSessionId, std::optional<NasPdu>& nasPdu, SNssai& sNssai,
    OCTET_STRING_t& pduSessionResourceSetupRequestTransfer) const {
  pduSessionId = m_PduSessionId;
  nasPdu       = m_NasPdu;
  sNssai       = m_SNssai;
  pduSessionResourceSetupRequestTransfer =
      m_PduSessionResourceSetupRequestTransfer;
}

//------------------------------------------------------------------------------
bool PduSessionResourceSetupItemSUReq::encode(
    Ngap_PDUSessionResourceSetupItemSUReq_t& pduSessionResourceItem) const {
  if (!m_PduSessionId.encode(pduSessionResourceItem.pDUSessionID)) return false;
  if (m_NasPdu.has_value()) {
    Ngap_NAS_PDU_t* naspdu =
        (Ngap_NAS_PDU_t*) calloc(1, sizeof(Ngap_NAS_PDU_t));
    if (!naspdu) return false;
    if (!m_NasPdu.value().encode(*naspdu)) {
      oai::utils::utils::free_wrapper((void**) &naspdu);
      return false;
    }
    pduSessionResourceItem.pDUSessionNAS_PDU = naspdu;
  }
  if (!m_SNssai.encode(pduSessionResourceItem.s_NSSAI)) return false;
  pduSessionResourceItem.pDUSessionResourceSetupRequestTransfer =
      m_PduSessionResourceSetupRequestTransfer;

  return true;
}

//------------------------------------------------------------------------------
bool PduSessionResourceSetupItemSUReq::decode(
    const Ngap_PDUSessionResourceSetupItemSUReq_t& pduSessionResourceItem) {
  if (!m_PduSessionId.decode(pduSessionResourceItem.pDUSessionID)) return false;
  if (!m_SNssai.decode(pduSessionResourceItem.s_NSSAI)) return false;

  if (pduSessionResourceItem.pDUSessionNAS_PDU) {
    NasPdu tmp = {};
    if (!tmp.decode(*pduSessionResourceItem.pDUSessionNAS_PDU)) return false;
    m_NasPdu = std::optional<NasPdu>(tmp);
  }

  m_PduSessionResourceSetupRequestTransfer =
      pduSessionResourceItem.pDUSessionResourceSetupRequestTransfer;

  return true;
}

}  // namespace oai::ngap
