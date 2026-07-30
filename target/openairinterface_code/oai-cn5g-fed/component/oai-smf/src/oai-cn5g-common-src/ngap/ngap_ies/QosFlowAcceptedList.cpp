/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "QosFlowAcceptedList.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
QosFlowAcceptedList::QosFlowAcceptedList() {}

//------------------------------------------------------------------------------
QosFlowAcceptedList::~QosFlowAcceptedList() {}

//------------------------------------------------------------------------------
void QosFlowAcceptedList::set(const std::vector<QosFlowAcceptedItem>& list) {
  m_ItemList = list;
  return;
}

//------------------------------------------------------------------------------
void QosFlowAcceptedList::get(std::vector<QosFlowAcceptedItem>& list) const {
  list = m_ItemList;
}

//------------------------------------------------------------------------------
void QosFlowAcceptedList::addItem(const QosFlowAcceptedItem& item) {
  m_ItemList.push_back(item);
}

//------------------------------------------------------------------------------
bool QosFlowAcceptedList::encode(Ngap_QosFlowAcceptedList_t& list) const {
  for (auto l : m_ItemList) {
    Ngap_QosFlowAcceptedItem_t* item = (Ngap_QosFlowAcceptedItem_t*) calloc(
        1, sizeof(Ngap_QosFlowAcceptedItem_t));
    if (!item) return false;
    if (!l.encode(*item)) return false;
    if (ASN_SEQUENCE_ADD(&list.list, item) != 0) return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool QosFlowAcceptedList::decode(const Ngap_QosFlowAcceptedList_t& list) {
  m_ItemList.clear();
  for (int i = 0; i < list.list.count; i++) {
    QosFlowAcceptedItem item = {};
    if (!item.decode(*list.list.array[i])) return false;
    m_ItemList.push_back(item);
  }
  return true;
}

}  // namespace oai::ngap
