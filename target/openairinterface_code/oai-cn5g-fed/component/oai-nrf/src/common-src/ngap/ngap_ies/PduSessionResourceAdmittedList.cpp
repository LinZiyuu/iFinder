/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceAdmittedList.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceAdmittedList::PduSessionResourceAdmittedList() {}

//------------------------------------------------------------------------------
PduSessionResourceAdmittedList::~PduSessionResourceAdmittedList() {}

//------------------------------------------------------------------------------
void PduSessionResourceAdmittedList::set(
    const std::vector<PduSessionResourceItem>& list) {
  m_ItemList = list;
}

//------------------------------------------------------------------------------
void PduSessionResourceAdmittedList::get(
    std::vector<PduSessionResourceItem>& list) const {
  list = m_ItemList;
}

//------------------------------------------------------------------------------
bool PduSessionResourceAdmittedList::encode(
    Ngap_PDUSessionResourceAdmittedList_t& list) const {
  for (auto& item : m_ItemList) {
    Ngap_PDUSessionResourceAdmittedItem_t* response =
        (Ngap_PDUSessionResourceAdmittedItem_t*) calloc(
            1, sizeof(Ngap_PDUSessionResourceAdmittedItem_t));
    if (!response) return false;
    if (!item.encode(*response)) return false;
    if (ASN_SEQUENCE_ADD(&list.list, response) != 0) return false;
  }

  return true;
}

//------------------------------------------------------------------------------
bool PduSessionResourceAdmittedList::decode(
    const Ngap_PDUSessionResourceAdmittedList_t& list) {
  for (int i = 0; i < list.list.count; i++) {
    PduSessionResourceItem item = {};
    if (!item.decode(*list.list.array[i])) return false;
    m_ItemList.push_back(item);
  }

  return true;
}

}  // namespace oai::ngap
