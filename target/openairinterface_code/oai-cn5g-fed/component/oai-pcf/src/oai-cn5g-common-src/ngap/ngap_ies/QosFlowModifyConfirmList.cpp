/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "QosFlowModifyConfirmList.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
QosFlowModifyConfirmList::QosFlowModifyConfirmList() {}

//------------------------------------------------------------------------------
QosFlowModifyConfirmList::~QosFlowModifyConfirmList() {}

//------------------------------------------------------------------------------
void QosFlowModifyConfirmList::set(
    const std::vector<QosFlowModifyConfirmItem>& list) {
  m_ItemList = list;
  return;
}

//------------------------------------------------------------------------------
void QosFlowModifyConfirmList::get(
    std::vector<QosFlowModifyConfirmItem>& list) const {
  list = m_ItemList;
}

//------------------------------------------------------------------------------
void QosFlowModifyConfirmList::addItem(const QosFlowModifyConfirmItem& item) {
  m_ItemList.push_back(item);
}

//------------------------------------------------------------------------------
bool QosFlowModifyConfirmList::encode(
    Ngap_QosFlowModifyConfirmList_t& list) const {
  for (auto l : m_ItemList) {
    Ngap_QosFlowModifyConfirmItem_t* item =
        (Ngap_QosFlowModifyConfirmItem_t*) calloc(
            1, sizeof(Ngap_QosFlowModifyConfirmItem_t));
    if (!item) return false;
    if (!l.encode(*item)) return false;
    if (ASN_SEQUENCE_ADD(&list.list, item) != 0) return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool QosFlowModifyConfirmList::decode(
    const Ngap_QosFlowModifyConfirmList_t& list) {
  m_ItemList.clear();
  for (int i = 0; i < list.list.count; i++) {
    QosFlowModifyConfirmItem item = {};
    if (!item.decode(*list.list.array[i])) return false;
    m_ItemList.push_back(item);
  }
  return true;
}

}  // namespace oai::ngap
