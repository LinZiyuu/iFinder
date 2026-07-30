/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceSetupItemCxtReq.hpp"

#include "utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceSetupItemCxtReq::PduSessionResourceSetupItemCxtReq() {
  m_NasPdu = std::nullopt;
}

//------------------------------------------------------------------------------
PduSessionResourceSetupItemCxtReq::~PduSessionResourceSetupItemCxtReq() {}

//------------------------------------------------------------------------------
void PduSessionResourceSetupItemCxtReq::set(
    const PduSessionId& pduSessionId, const std::optional<NasPdu>& nasPdu,
    const SNssai& sNssai,
    const OCTET_STRING_t& pduSessionResourceSetupRequestTransfer) {
  m_PduSessionId = pduSessionId;
  m_NasPdu       = nasPdu;
  m_SNssai       = sNssai;
  m_PduSessionResourceSetupRequestTransfer =
      pduSessionResourceSetupRequestTransfer;
}

//------------------------------------------------------------------------------
void PduSessionResourceSetupItemCxtReq::get(
    PduSessionId& pduSessionId, std::optional<NasPdu>& nasPdu, SNssai& sNssai,
    OCTET_STRING_t& pduSessionResourceSetupRequestTransfer) const {
  pduSessionId = m_PduSessionId;
  nasPdu       = m_NasPdu;
  sNssai       = m_SNssai;
  pduSessionResourceSetupRequestTransfer =
      m_PduSessionResourceSetupRequestTransfer;
}

//------------------------------------------------------------------------------
bool PduSessionResourceSetupItemCxtReq::encode(
    Ngap_PDUSessionResourceSetupItemCxtReq_t& pduSessionResourceSetupItemCxtReq)
    const {
  if (!m_PduSessionId.encode(pduSessionResourceSetupItemCxtReq.pDUSessionID))
    return false;

  if (m_NasPdu.has_value()) {
    Ngap_NAS_PDU_t* naspdu =
        (Ngap_NAS_PDU_t*) calloc(1, sizeof(Ngap_NAS_PDU_t));
    if (!naspdu) return false;
    if (!m_NasPdu.value().encode(*naspdu)) {
      oai::utils::utils::free_wrapper((void**) &naspdu);
      return false;
    }
    pduSessionResourceSetupItemCxtReq.nAS_PDU = naspdu;
  }

  if (!m_SNssai.encode(pduSessionResourceSetupItemCxtReq.s_NSSAI)) return false;
  pduSessionResourceSetupItemCxtReq.pDUSessionResourceSetupRequestTransfer =
      m_PduSessionResourceSetupRequestTransfer;

  return true;
}

//------------------------------------------------------------------------------
bool PduSessionResourceSetupItemCxtReq::decode(
    const Ngap_PDUSessionResourceSetupItemCxtReq_t&
        pduSessionResourceSetupItemCxtReq) {
  if (!m_PduSessionId.decode(pduSessionResourceSetupItemCxtReq.pDUSessionID))
    return false;
  if (!m_SNssai.decode(pduSessionResourceSetupItemCxtReq.s_NSSAI)) return false;

  if (pduSessionResourceSetupItemCxtReq.nAS_PDU) {
    NasPdu tmp = {};
    if (!tmp.decode(*pduSessionResourceSetupItemCxtReq.nAS_PDU)) return false;
    m_NasPdu = std::optional<NasPdu>(tmp);
  }

  m_PduSessionResourceSetupRequestTransfer =
      pduSessionResourceSetupItemCxtReq.pDUSessionResourceSetupRequestTransfer;

  return true;
}

}  // namespace oai::ngap
