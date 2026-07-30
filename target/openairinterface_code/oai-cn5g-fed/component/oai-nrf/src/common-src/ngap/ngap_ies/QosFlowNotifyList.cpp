/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "QosFlowNotifyList.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
QosFlowNotifyList::QosFlowNotifyList() {}

//------------------------------------------------------------------------------
QosFlowNotifyList::~QosFlowNotifyList() {}

//------------------------------------------------------------------------------
void QosFlowNotifyList::set(const std::vector<QosFlowNotifyItem>& list) {
  m_ItemList = list;
  return;
}

//------------------------------------------------------------------------------
void QosFlowNotifyList::get(std::vector<QosFlowNotifyItem>& list) const {
  list = m_ItemList;
}

//------------------------------------------------------------------------------
void QosFlowNotifyList::addItem(const QosFlowNotifyItem& item) {
  m_ItemList.push_back(item);
}

//------------------------------------------------------------------------------
bool QosFlowNotifyList::encode(Ngap_QosFlowNotifyList_t& list) const {
  for (auto l : m_ItemList) {
    Ngap_QosFlowNotifyItem_t* item =
        (Ngap_QosFlowNotifyItem_t*) calloc(1, sizeof(Ngap_QosFlowNotifyItem_t));
    if (!item) return false;
    if (!l.encode(*item)) return false;
    if (ASN_SEQUENCE_ADD(&list.list, item) != 0) return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool QosFlowNotifyList::decode(const Ngap_QosFlowNotifyList_t& list) {
  m_ItemList.clear();
  for (int i = 0; i < list.list.count; i++) {
    QosFlowNotifyItem item = {};
    if (!item.decode(*list.list.array[i])) return false;
    m_ItemList.push_back(item);
  }
  return true;
}

}  // namespace oai::ngap
