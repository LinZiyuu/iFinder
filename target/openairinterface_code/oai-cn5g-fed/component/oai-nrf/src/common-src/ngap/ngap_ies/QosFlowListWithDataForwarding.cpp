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
void QosFlowListWithDataForwarding::set(
    const std::vector<QosFlowItemWithDataForwarding>& list) {
  uint8_t number_items =
      (list.size() > KMaxNoOfQosFlows) ? KMaxNoOfQosFlows : list.size();
  m_ItemList.insert(
      m_ItemList.begin(), list.begin(), list.begin() + number_items);
}

//------------------------------------------------------------------------------
void QosFlowListWithDataForwarding::get(
    std::vector<QosFlowItemWithDataForwarding>& list) const {
  list = m_ItemList;
}

//------------------------------------------------------------------------------
bool QosFlowListWithDataForwarding::decode(
    const Ngap_QosFlowListWithDataForwarding& list) {
  for (int i = 0; i < list.list.count; i++) {
    QosFlowItemWithDataForwarding item = {};
    if (!item.decode(*list.list.array[i])) return false;
    m_ItemList.push_back(item);
  }
  return true;
}
}  // namespace oai::ngap
