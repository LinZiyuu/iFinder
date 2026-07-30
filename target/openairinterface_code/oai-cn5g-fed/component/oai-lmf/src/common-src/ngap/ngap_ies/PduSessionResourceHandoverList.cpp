/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceHandoverList.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceHandoverList::PduSessionResourceHandoverList() {}

//------------------------------------------------------------------------------
PduSessionResourceHandoverList::~PduSessionResourceHandoverList() {}

//------------------------------------------------------------------------------
void PduSessionResourceHandoverList::set(
    const std::vector<PduSessionResourceItem>& list) {
  m_ItemList = list;
}

//------------------------------------------------------------------------------
void PduSessionResourceHandoverList::get(
    std::vector<PduSessionResourceItem>& list) const {
  list = m_ItemList;
}

//------------------------------------------------------------------------------
bool PduSessionResourceHandoverList::encode(
    Ngap_PDUSessionResourceHandoverList_t& list) const {
  for (auto& item : m_ItemList) {
    Ngap_PDUSessionResourceHandoverItem_t* handoverItem =
        (Ngap_PDUSessionResourceHandoverItem_t*) calloc(
            1, sizeof(Ngap_PDUSessionResourceHandoverItem_t));

    if (!handoverItem) return false;
    if (!item.encode(*handoverItem)) return false;
    if (ASN_SEQUENCE_ADD(&list.list, handoverItem) != 0) return false;
  }

  return true;
}

//------------------------------------------------------------------------------
bool PduSessionResourceHandoverList::decode(
    const Ngap_PDUSessionResourceHandoverList_t& list) {
  for (int i = 0; i < list.list.count; i++) {
    PduSessionResourceItem item = {};

    if (!item.decode(*list.list.array[i])) return false;
    m_ItemList.push_back(item);
  }
  return true;
}

}  // namespace oai::ngap
