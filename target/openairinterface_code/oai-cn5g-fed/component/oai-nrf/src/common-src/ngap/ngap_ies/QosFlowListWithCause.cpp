/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "QosFlowListWithCause.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
QosFlowListWithCause::QosFlowListWithCause() {}

//------------------------------------------------------------------------------
QosFlowListWithCause::~QosFlowListWithCause() {}

//------------------------------------------------------------------------------
void QosFlowListWithCause::set(const std::vector<QosFlowWithCauseItem>& list) {
  m_ItemList = list;
}

//------------------------------------------------------------------------------
void QosFlowListWithCause::get(std::vector<QosFlowWithCauseItem>& list) const {
  list = m_ItemList;
}

//------------------------------------------------------------------------------
void QosFlowListWithCause::addItem(const QosFlowWithCauseItem& item) {
  m_ItemList.push_back(item);
}

//------------------------------------------------------------------------------
bool QosFlowListWithCause::encode(
    Ngap_QosFlowListWithCause_t& QosFlowListWithCause) const {
  for (auto l : m_ItemList) {
    Ngap_QosFlowWithCauseItem_t* item = (Ngap_QosFlowWithCauseItem_t*) calloc(
        1, sizeof(Ngap_QosFlowWithCauseItem_t));
    if (!item) return false;
    if (!l.encode(*item)) return false;
    if (ASN_SEQUENCE_ADD(&QosFlowListWithCause.list, item) != 0) return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool QosFlowListWithCause::decode(
    const Ngap_QosFlowListWithCause_t& QosFlowListWithCause) {
  m_ItemList.clear();
  for (int i = 0; i < QosFlowListWithCause.list.count; i++) {
    QosFlowWithCauseItem item = {};
    if (!item.decode(*QosFlowListWithCause.list.array[i])) return false;
    m_ItemList.push_back(item);
  }
  return true;
}
}  // namespace oai::ngap
