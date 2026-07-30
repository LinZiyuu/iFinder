/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "QosFlowParametersList.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
QosFlowParametersList::QosFlowParametersList() {}

//------------------------------------------------------------------------------
QosFlowParametersList::~QosFlowParametersList() {}

//------------------------------------------------------------------------------
void QosFlowParametersList::set(
    const std::vector<QosFlowParametersItem>& list) {
  m_ItemList = list;
  return;
}

//------------------------------------------------------------------------------
void QosFlowParametersList::get(
    std::vector<QosFlowParametersItem>& list) const {
  list = m_ItemList;
}

//------------------------------------------------------------------------------
void QosFlowParametersList::addItem(const QosFlowParametersItem& item) {
  m_ItemList.push_back(item);
}

//------------------------------------------------------------------------------
bool QosFlowParametersList::encode(Ngap_QosFlowParametersList_t& list) const {
  for (auto l : m_ItemList) {
    Ngap_QosFlowParametersItem_t* item = (Ngap_QosFlowParametersItem_t*) calloc(
        1, sizeof(Ngap_QosFlowParametersItem_t));
    if (!item) return false;
    if (!l.encode(*item)) return false;
    if (ASN_SEQUENCE_ADD(&list.list, item) != 0) return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool QosFlowParametersList::decode(const Ngap_QosFlowParametersList_t& list) {
  m_ItemList.clear();
  for (int i = 0; i < list.list.count; i++) {
    QosFlowParametersItem item = {};
    if (!item.decode(*list.list.array[i])) return false;
    m_ItemList.push_back(item);
  }
  return true;
}

}  // namespace oai::ngap
