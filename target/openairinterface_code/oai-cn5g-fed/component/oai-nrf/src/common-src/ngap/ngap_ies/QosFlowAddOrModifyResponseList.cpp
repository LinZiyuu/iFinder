/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "QosFlowAddOrModifyResponseList.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
QosFlowAddOrModifyResponseList::QosFlowAddOrModifyResponseList() {}

//------------------------------------------------------------------------------
QosFlowAddOrModifyResponseList::~QosFlowAddOrModifyResponseList() {}

//------------------------------------------------------------------------------
void QosFlowAddOrModifyResponseList::set(
    const std::vector<QosFlowAddOrModifyResponseItem>& list) {
  m_ItemList = list;
  return;
}

//------------------------------------------------------------------------------
void QosFlowAddOrModifyResponseList::get(
    std::vector<QosFlowAddOrModifyResponseItem>& list) const {
  list = m_ItemList;
}

//------------------------------------------------------------------------------
void QosFlowAddOrModifyResponseList::addItem(
    const QosFlowAddOrModifyResponseItem& item) {
  m_ItemList.push_back(item);
}

//------------------------------------------------------------------------------
bool QosFlowAddOrModifyResponseList::encode(
    Ngap_QosFlowAddOrModifyResponseList_t& list) const {
  for (auto l : m_ItemList) {
    Ngap_QosFlowAddOrModifyResponseItem_t* item =
        (Ngap_QosFlowAddOrModifyResponseItem_t*) calloc(
            1, sizeof(Ngap_QosFlowAddOrModifyResponseItem_t));
    if (!item) return false;
    if (!l.encode(*item)) return false;
    if (ASN_SEQUENCE_ADD(&list.list, item) != 0) return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool QosFlowAddOrModifyResponseList::decode(
    const Ngap_QosFlowAddOrModifyResponseList_t& list) {
  m_ItemList.clear();
  for (int i = 0; i < list.list.count; i++) {
    QosFlowAddOrModifyResponseItem item = {};
    if (!item.decode(*list.list.array[i])) return false;
    m_ItemList.push_back(item);
  }
  return true;
}

}  // namespace oai::ngap
