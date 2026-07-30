/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "QosFlowListWithDataForwarding.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
QosFlowListWithDataForwarding::QosFlowListWithDataForwarding() {}

//------------------------------------------------------------------------------
QosFlowListWithDataForwarding::~QosFlowListWithDataForwarding() {}

//------------------------------------------------------------------------------
bool QosFlowListWithDataForwarding::decode(
    const Ngap_QosFlowListWithDataForwarding& qosFlowSetupResponseList) {
  for (int i = 0; i < qosFlowSetupResponseList.list.count; i++) {
    QosFlowItemWithDataForWarding item = {};
    if (!item.decode(*qosFlowSetupResponseList.list.array[i])) return false;
    m_ItemList.push_back(item);
  }
  return true;
}

//------------------------------------------------------------------------------
void QosFlowListWithDataForwarding::set(
    const std::vector<QosFlowItemWithDataForWarding>& list) {
  uint8_t number_items =
      (list.size() > kMaxNoQoSFlows) ? kMaxNoQoSFlows : list.size();
  m_ItemList.insert(
      m_ItemList.begin(), list.begin(), list.begin() + number_items);
}

//------------------------------------------------------------------------------
void QosFlowListWithDataForwarding::get(
    std::vector<QosFlowItemWithDataForWarding>& list) const {
  list = m_ItemList;
}

}  // namespace oai::ngap
