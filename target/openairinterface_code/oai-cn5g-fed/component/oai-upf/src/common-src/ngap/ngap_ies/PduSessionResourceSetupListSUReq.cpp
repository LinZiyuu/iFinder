/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceSetupListSUReq.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceSetupListSUReq::PduSessionResourceSetupListSUReq() {}

//------------------------------------------------------------------------------
PduSessionResourceSetupListSUReq::~PduSessionResourceSetupListSUReq() {}

//------------------------------------------------------------------------------
void PduSessionResourceSetupListSUReq::set(
    const std::vector<PduSessionResourceSetupItemSUReq>& list) {
  m_ItemList = list;
}

//------------------------------------------------------------------------------
void PduSessionResourceSetupListSUReq::get(
    std::vector<PduSessionResourceSetupItemSUReq>& list) const {
  list = m_ItemList;
}

//------------------------------------------------------------------------------
bool PduSessionResourceSetupListSUReq::encode(
    Ngap_PDUSessionResourceSetupListSUReq_t& pduSessionResourceList) const {
  for (auto& item : m_ItemList) {
    Ngap_PDUSessionResourceSetupItemSUReq_t* request =
        (Ngap_PDUSessionResourceSetupItemSUReq_t*) calloc(
            1, sizeof(Ngap_PDUSessionResourceSetupItemSUReq_t));
    if (!request) return false;
    if (!item.encode(*request)) return false;
    if (ASN_SEQUENCE_ADD(&pduSessionResourceList.list, request) != 0)
      return false;
  }

  return true;
}

//------------------------------------------------------------------------------
bool PduSessionResourceSetupListSUReq::decode(
    const Ngap_PDUSessionResourceSetupListSUReq_t& pduSessionResourceList) {
  for (int i = 0; i < pduSessionResourceList.list.count; i++) {
    PduSessionResourceSetupItemSUReq item = {};
    if (!item.decode(*pduSessionResourceList.list.array[i])) return false;
    m_ItemList.push_back(item);
  }

  return true;
}

}  // namespace oai::ngap
