/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceModifyListModReq.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceModifyListModReq::PduSessionResourceModifyListModReq() {}

//------------------------------------------------------------------------------
PduSessionResourceModifyListModReq::~PduSessionResourceModifyListModReq() {}

//------------------------------------------------------------------------------
void PduSessionResourceModifyListModReq::set(
    const std::vector<PduSessionResourceModifyItemModReq>& list) {
  m_ItemList = list;
}

//------------------------------------------------------------------------------
bool PduSessionResourceModifyListModReq::encode(
    Ngap_PDUSessionResourceModifyListModReq_t& pduSessionResourceList) const {
  for (auto pdu : m_ItemList) {
    Ngap_PDUSessionResourceModifyItemModReq_t* item =
        (Ngap_PDUSessionResourceModifyItemModReq_t*) calloc(
            1, sizeof(Ngap_PDUSessionResourceModifyItemModReq_t));

    if (!item) return false;
    if (!pdu.encode(*item)) return false;
    if (ASN_SEQUENCE_ADD(&pduSessionResourceList.list, item) != 0) return false;
  }

  return true;
}

//------------------------------------------------------------------------------
bool PduSessionResourceModifyListModReq::decode(
    const Ngap_PDUSessionResourceModifyListModReq_t& pduSessionResourceList) {
  uint32_t numberofPDUSessions = pduSessionResourceList.list.count;

  for (int i = 0; i < numberofPDUSessions; i++) {
    PduSessionResourceModifyItemModReq item = {};

    if (!item.decode(*pduSessionResourceList.list.array[i])) return false;
    m_ItemList.push_back(item);
  }

  return true;
}

//------------------------------------------------------------------------------
void PduSessionResourceModifyListModReq::get(
    std::vector<PduSessionResourceModifyItemModReq>& list) const {
  list = m_ItemList;
}

}  // namespace oai::ngap
