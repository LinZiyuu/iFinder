/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceListHandoverRqd.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceListHandoverRqd::PduSessionResourceListHandoverRqd() {}

//------------------------------------------------------------------------------
PduSessionResourceListHandoverRqd::~PduSessionResourceListHandoverRqd() {}

//------------------------------------------------------------------------------
void PduSessionResourceListHandoverRqd::set(
    const std::vector<PduSessionResourceItem>& list) {
  m_ItemList = list;
}

//------------------------------------------------------------------------------
void PduSessionResourceListHandoverRqd::get(
    std::vector<PduSessionResourceItem>& list) const {
  list = m_ItemList;
}

//------------------------------------------------------------------------------
bool PduSessionResourceListHandoverRqd::encode(
    Ngap_PDUSessionResourceListHORqd_t& list) const {
  for (auto& item : m_ItemList) {
    Ngap_PDUSessionResourceItemHORqd_t* itemHORqd =
        (Ngap_PDUSessionResourceItemHORqd_t*) calloc(
            1, sizeof(Ngap_PDUSessionResourceItemHORqd_t));
    if (!itemHORqd) return false;
    if (!item.encode(*itemHORqd)) return false;
    if (ASN_SEQUENCE_ADD(&list.list, itemHORqd) != 0) return false;
  }

  return true;
}

//------------------------------------------------------------------------------
bool PduSessionResourceListHandoverRqd::decode(
    const Ngap_PDUSessionResourceListHORqd_t& list) {
  for (int i = 0; i < list.list.count; i++) {
    PduSessionResourceItem item = {};
    if (!item.decode(*list.list.array[i])) return false;
    m_ItemList.push_back(item);
  }

  return true;
}
}  // namespace oai::ngap
