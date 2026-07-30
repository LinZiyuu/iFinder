/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "UeAssociatedLogicalNgConnectionList.hpp"
#include "utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
UeAssociatedLogicalNgConnectionList::UeAssociatedLogicalNgConnectionList() {}

//------------------------------------------------------------------------------
UeAssociatedLogicalNgConnectionList::~UeAssociatedLogicalNgConnectionList() {}

//------------------------------------------------------------------------------
void UeAssociatedLogicalNgConnectionList::set(
    const std::vector<UeAssociatedLogicalNgConnectionItem>& list) {
  m_ItemList = list;
  return;
}

//------------------------------------------------------------------------------
void UeAssociatedLogicalNgConnectionList::get(
    std::vector<UeAssociatedLogicalNgConnectionItem>& list) const {
  list = m_ItemList;
}

//------------------------------------------------------------------------------
void UeAssociatedLogicalNgConnectionList::addItem(
    UeAssociatedLogicalNgConnectionItem& item) {
  m_ItemList.push_back(item);
}

//------------------------------------------------------------------------------
bool UeAssociatedLogicalNgConnectionList::encode(
    Ngap_UE_associatedLogicalNG_connectionList_t& list) const {
  for (auto l : m_ItemList) {
    Ngap_UE_associatedLogicalNG_connectionItem_t* item =
        (Ngap_UE_associatedLogicalNG_connectionItem_t*) calloc(
            1, sizeof(Ngap_UE_associatedLogicalNG_connectionItem_t));
    if (!item) return false;
    if (!l.encode(*item)) return false;
    if (ASN_SEQUENCE_ADD(&list.list, item) != 0) return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool UeAssociatedLogicalNgConnectionList::decode(
    const Ngap_UE_associatedLogicalNG_connectionList_t& list) {
  m_ItemList.clear();
  for (int i = 0; i < list.list.count; i++) {
    UeAssociatedLogicalNgConnectionItem item = {};
    if (!item.decode(*list.list.array[i])) return false;
    m_ItemList.push_back(item);
  }
  return true;
}

}  // namespace oai::ngap
