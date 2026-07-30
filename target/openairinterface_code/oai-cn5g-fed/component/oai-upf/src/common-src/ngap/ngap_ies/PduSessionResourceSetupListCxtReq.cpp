/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceSetupListCxtReq.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceSetupListCxtReq::PduSessionResourceSetupListCxtReq() {}

//------------------------------------------------------------------------------
PduSessionResourceSetupListCxtReq::~PduSessionResourceSetupListCxtReq() {}

//------------------------------------------------------------------------------
void PduSessionResourceSetupListCxtReq::set(
    const std::vector<PduSessionResourceSetupItemCxtReq>& itemList) {
  m_ItemList = itemList;
}

//------------------------------------------------------------------------------
void PduSessionResourceSetupListCxtReq::get(
    std::vector<PduSessionResourceSetupItemCxtReq>& itemList) const {}

//------------------------------------------------------------------------------
bool PduSessionResourceSetupListCxtReq::encode(
    Ngap_PDUSessionResourceSetupListCxtReq_t& pduSessionResourceSetupListCxtReq)
    const {
  for (std::vector<PduSessionResourceSetupItemCxtReq>::const_iterator it =
           m_ItemList.begin();
       it < m_ItemList.end(); ++it) {
    Ngap_PDUSessionResourceSetupItemCxtReq_t* request =
        (Ngap_PDUSessionResourceSetupItemCxtReq_t*) calloc(
            1, sizeof(Ngap_PDUSessionResourceSetupItemCxtReq_t));
    if (!request) return false;
    if (!it->encode(*request)) return false;
    if (ASN_SEQUENCE_ADD(&pduSessionResourceSetupListCxtReq.list, request) != 0)
      return false;
  }

  return true;
}

//------------------------------------------------------------------------------
bool PduSessionResourceSetupListCxtReq::decode(
    const Ngap_PDUSessionResourceSetupListCxtReq_t&
        pduSessionResourceSetupListCxtReq) {
  m_ItemList.reserve(pduSessionResourceSetupListCxtReq.list.count);

  for (int i = 0; i < pduSessionResourceSetupListCxtReq.list.count; i++) {
    PduSessionResourceSetupItemCxtReq item = {};
    if (!item.decode(*pduSessionResourceSetupListCxtReq.list.array[i]))
      return false;
    m_ItemList.push_back(item);
  }

  return true;
}

}  // namespace oai::ngap
