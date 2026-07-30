/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "QosFlowPerTnlInformationList.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
QosFlowPerTnlInformationList::QosFlowPerTnlInformationList() {}

//------------------------------------------------------------------------------
QosFlowPerTnlInformationList::~QosFlowPerTnlInformationList() {}

//------------------------------------------------------------------------------
void QosFlowPerTnlInformationList::set(
    const std::vector<QosFlowPerTnlInformationItem>& list) {
  uint8_t number_items = (list.size() > KMaxNoOfMultiConnectivityMinusOne) ?
                             KMaxNoOfMultiConnectivityMinusOne :
                             list.size();
  m_ItemList.insert(
      m_ItemList.begin(), list.begin(), list.begin() + number_items);
}

//------------------------------------------------------------------------------
void QosFlowPerTnlInformationList::get(
    std::vector<QosFlowPerTnlInformationItem>& list) const {
  list = m_ItemList;
}

//------------------------------------------------------------------------------
bool QosFlowPerTnlInformationList::encode(
    Ngap_QosFlowPerTNLInformationList_t& qosFlowPerTnlInformationList) const {
  for (int i = 0; i < m_ItemList.size(); i++) {
    Ngap_QosFlowPerTNLInformationItem_t* item =
        (Ngap_QosFlowPerTNLInformationItem_t*) calloc(
            1, sizeof(Ngap_QosFlowPerTNLInformationItem_t));
    if (!item) return false;
    if (!m_ItemList[i].encode(*item)) return false;
    if (ASN_SEQUENCE_ADD(&qosFlowPerTnlInformationList.list, item) != 0)
      return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool QosFlowPerTnlInformationList::decode(
    const Ngap_QosFlowPerTNLInformationList_t& qosFlowPerTnlInformationList) {
  for (int i = 0; i < qosFlowPerTnlInformationList.list.count; i++) {
    QosFlowPerTnlInformationItem item = {};
    if (!item.decode(*qosFlowPerTnlInformationList.list.array[i])) return false;
    m_ItemList.push_back(item);
  }
  return true;
}

}  // namespace oai::ngap
