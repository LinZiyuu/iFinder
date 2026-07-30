/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "QosFlowAddOrModifyRequestList.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
QosFlowAddOrModifyRequestList::QosFlowAddOrModifyRequestList() {}

//------------------------------------------------------------------------------
QosFlowAddOrModifyRequestList::~QosFlowAddOrModifyRequestList() {}

//------------------------------------------------------------------------------
void QosFlowAddOrModifyRequestList::set(
    const std::vector<QosFlowAddOrModifyRequestItem>& list) {
  m_ItemList = list;
  return;
}

//------------------------------------------------------------------------------
void QosFlowAddOrModifyRequestList::get(
    std::vector<QosFlowAddOrModifyRequestItem>& list) const {
  list = m_ItemList;
}

//------------------------------------------------------------------------------
void QosFlowAddOrModifyRequestList::addItem(
    const QosFlowAddOrModifyRequestItem& item) {
  m_ItemList.push_back(item);
}

//------------------------------------------------------------------------------
bool QosFlowAddOrModifyRequestList::encode(
    Ngap_QosFlowAddOrModifyRequestList_t& list) const {
  for (auto l : m_ItemList) {
    Ngap_QosFlowAddOrModifyRequestItem_t* item =
        (Ngap_QosFlowAddOrModifyRequestItem_t*) calloc(
            1, sizeof(Ngap_QosFlowAddOrModifyRequestItem_t));
    if (!item) return false;
    if (!l.encode(*item)) return false;
    if (ASN_SEQUENCE_ADD(&list.list, item) != 0) return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool QosFlowAddOrModifyRequestList::decode(
    const Ngap_QosFlowAddOrModifyRequestList_t& list) {
  m_ItemList.clear();
  for (int i = 0; i < list.list.count; i++) {
    QosFlowAddOrModifyRequestItem item = {};
    if (!item.decode(*list.list.array[i])) return false;
    m_ItemList.push_back(item);
  }
  return true;
}

}  // namespace oai::ngap
