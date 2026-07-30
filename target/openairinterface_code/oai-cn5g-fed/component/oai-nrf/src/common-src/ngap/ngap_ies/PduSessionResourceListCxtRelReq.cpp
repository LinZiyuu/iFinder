/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceListCxtRelReq.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceListCxtRelReq::PduSessionResourceListCxtRelReq() {}

//------------------------------------------------------------------------------
PduSessionResourceListCxtRelReq::~PduSessionResourceListCxtRelReq() {}

//------------------------------------------------------------------------------
void PduSessionResourceListCxtRelReq::set(
    const std::vector<PduSessionResourceItemCxtRelReq>& list) {
  m_ItemList.clear();
  for (auto i : list) {
    m_ItemList.push_back(i);
  }
}

//------------------------------------------------------------------------------
void PduSessionResourceListCxtRelReq::get(
    std::vector<PduSessionResourceItemCxtRelReq>& list) const {
  list.clear();
  for (auto i : m_ItemList) {
    list.push_back(i);
  }
}

//------------------------------------------------------------------------------
bool PduSessionResourceListCxtRelReq::encode(
    Ngap_PDUSessionResourceListCxtRelReq_t& pduSessionResourceList) const {
  for (auto& cxt_rel_req : m_ItemList) {
    Ngap_PDUSessionResourceItemCxtRelReq_t* item =
        (Ngap_PDUSessionResourceItemCxtRelReq_t*) calloc(
            1, sizeof(Ngap_PDUSessionResourceItemCxtRelReq_t));
    if (!item) return false;
    if (!cxt_rel_req.encode(*item)) return false;
    if (ASN_SEQUENCE_ADD(&pduSessionResourceList.list, item) != 0) return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool PduSessionResourceListCxtRelReq::decode(
    const Ngap_PDUSessionResourceListCxtRelReq_t& pduSessionResourceList) {
  for (int i = 0; i < pduSessionResourceList.list.count; i++) {
    PduSessionResourceItemCxtRelReq item = {};
    if (!item.decode(*pduSessionResourceList.list.array[i])) return false;
    m_ItemList.push_back(item);
  }
  return true;
}

}  // namespace oai::ngap
