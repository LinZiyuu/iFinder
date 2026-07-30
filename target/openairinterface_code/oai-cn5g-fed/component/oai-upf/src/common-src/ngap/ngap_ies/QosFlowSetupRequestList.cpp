/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "QosFlowSetupRequestList.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
QosFlowSetupRequestList::QosFlowSetupRequestList() {}

//------------------------------------------------------------------------------
QosFlowSetupRequestList::~QosFlowSetupRequestList() {}

//------------------------------------------------------------------------------
void QosFlowSetupRequestList::set(
    const std::vector<QosFlowSetupRequestItem>& list) {
  uint8_t number_items =
      (list.size() > kMaxNoOfQoSFlows) ? kMaxNoOfQoSFlows : list.size();
  m_ItemList.insert(
      m_ItemList.begin(), list.begin(), list.begin() + number_items);
}

//------------------------------------------------------------------------------
void QosFlowSetupRequestList::get(
    std::vector<QosFlowSetupRequestItem>& list) const {
  list = m_ItemList;
}

//------------------------------------------------------------------------------
bool QosFlowSetupRequestList::encode(
    Ngap_QosFlowSetupRequestList_t& qosFlowSetupRequestList) const {
  for (int i = 0; i < m_ItemList.size(); i++) {
    Ngap_QosFlowSetupRequestItem_t* item =
        (Ngap_QosFlowSetupRequestItem_t*) calloc(
            1, sizeof(Ngap_QosFlowSetupRequestItem_t));
    if (!item) return false;
    if (!m_ItemList[i].encode(*item)) return false;
    if (ASN_SEQUENCE_ADD(&qosFlowSetupRequestList.list, item) != 0)
      return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool QosFlowSetupRequestList::decode(
    const Ngap_QosFlowSetupRequestList_t& qosFlowSetupRequestList) {
  for (int i = 0; i < qosFlowSetupRequestList.list.count; i++) {
    QosFlowSetupRequestItem item = {};
    if (!item.decode(*qosFlowSetupRequestList.list.array[i])) return false;
    m_ItemList.push_back(item);
  }
  return true;
}

}  // namespace oai::ngap
