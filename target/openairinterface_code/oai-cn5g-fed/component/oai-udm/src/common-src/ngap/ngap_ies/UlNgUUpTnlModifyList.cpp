/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "UlNgUUpTnlModifyList.hpp"

#include "utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
UlNgUUpTnlModifyList::UlNgUUpTnlModifyList() {}

//------------------------------------------------------------------------------
UlNgUUpTnlModifyList::~UlNgUUpTnlModifyList() {}

//------------------------------------------------------------------------------
void UlNgUUpTnlModifyList::set(const std::vector<UlNgUUpTnlModifyItem>& list) {
  m_ItemList = list;
  return;
}

//------------------------------------------------------------------------------
void UlNgUUpTnlModifyList::get(std::vector<UlNgUUpTnlModifyItem>& list) const {
  list = m_ItemList;
}

//------------------------------------------------------------------------------
void UlNgUUpTnlModifyList::addItem(const UlNgUUpTnlModifyItem& item) {
  m_ItemList.push_back(item);
}

//------------------------------------------------------------------------------
bool UlNgUUpTnlModifyList::encode(Ngap_UL_NGU_UP_TNLModifyList_t& list) const {
  for (auto l : m_ItemList) {
    Ngap_UL_NGU_UP_TNLModifyItem_t* item =
        (Ngap_UL_NGU_UP_TNLModifyItem_t*) calloc(
            1, sizeof(Ngap_UL_NGU_UP_TNLModifyItem_t));
    if (!item) return false;
    if (!l.encode(*item)) return false;
    if (ASN_SEQUENCE_ADD(&list.list, item) != 0) return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool UlNgUUpTnlModifyList::decode(const Ngap_UL_NGU_UP_TNLModifyList_t& list) {
  m_ItemList.clear();
  for (int i = 0; i < list.list.count; i++) {
    UlNgUUpTnlModifyItem item = {};
    if (!item.decode(*list.list.array[i])) return false;
    m_ItemList.push_back(item);
  }
  return true;
}

}  // namespace oai::ngap
