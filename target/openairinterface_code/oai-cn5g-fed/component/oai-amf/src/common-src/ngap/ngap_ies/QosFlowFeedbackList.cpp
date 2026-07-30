/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "QosFlowFeedbackList.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
QosFlowFeedbackList::QosFlowFeedbackList() {}

//------------------------------------------------------------------------------
QosFlowFeedbackList::~QosFlowFeedbackList() {}

//------------------------------------------------------------------------------
void QosFlowFeedbackList::set(const std::vector<QosFlowFeedbackItem>& list) {
  m_ItemList = list;
  return;
}

//------------------------------------------------------------------------------
void QosFlowFeedbackList::get(std::vector<QosFlowFeedbackItem>& list) const {
  list = m_ItemList;
}

//------------------------------------------------------------------------------
void QosFlowFeedbackList::addItem(const QosFlowFeedbackItem& item) {
  m_ItemList.push_back(item);
}

//------------------------------------------------------------------------------
bool QosFlowFeedbackList::encode(Ngap_QosFlowFeedbackList_t& list) const {
  for (auto l : m_ItemList) {
    Ngap_QosFlowFeedbackItem_t* item = (Ngap_QosFlowFeedbackItem_t*) calloc(
        1, sizeof(Ngap_QosFlowFeedbackItem_t));
    if (!item) return false;
    if (!l.encode(*item)) return false;
    if (ASN_SEQUENCE_ADD(&list.list, item) != 0) return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool QosFlowFeedbackList::decode(const Ngap_QosFlowFeedbackList_t& list) {
  m_ItemList.clear();
  for (int i = 0; i < list.list.count; i++) {
    QosFlowFeedbackItem item = {};
    if (!item.decode(*list.list.array[i])) return false;
    m_ItemList.push_back(item);
  }
  return true;
}

}  // namespace oai::ngap
