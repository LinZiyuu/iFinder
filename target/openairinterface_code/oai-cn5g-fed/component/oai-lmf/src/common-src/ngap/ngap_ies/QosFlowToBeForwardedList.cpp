/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "QosFlowToBeForwardedList.hpp"

#include "logger.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
QosFlowToBeForwardedList::QosFlowToBeForwardedList() {}

//------------------------------------------------------------------------------
void QosFlowToBeForwardedList::set(
    const std::vector<QosFlowToBeForwardedItem>& qosList) {
  uint8_t number_items =
      (qosList.size() > kMaxNoOfQosFlows) ? kMaxNoOfQosFlows : qosList.size();
  m_ItemList.insert(
      m_ItemList.begin(), qosList.begin(), qosList.begin() + number_items);
}

//------------------------------------------------------------------------------
bool QosFlowToBeForwardedList::encode(
    Ngap_QosFlowToBeForwardedList*& qosList) const {
  qosList = (Ngap_QosFlowToBeForwardedList_t*) calloc(
      1, sizeof(Ngap_QosFlowToBeForwardedList_t));
  for (int i = 0; i < m_ItemList.size(); i++) {
    Ngap_QosFlowToBeForwardedItem_t* response =
        (Ngap_QosFlowToBeForwardedItem_t*) calloc(
            1, sizeof(Ngap_QosFlowToBeForwardedItem_t));
    if (!response) return false;
    if (!m_ItemList[i].encode(*response)) {
      Logger::ngap().debug("Encode QosFlowTowardedItem error");
      return false;
    }
    Logger::ngap().debug("QFI %d", response->qosFlowIdentifier);

    if (ASN_SEQUENCE_ADD(&qosList->list, response) != 0) {
      Logger::ngap().debug("Encode QosFlowTowardedList error");
      return false;
    }
  }
  return true;
}
}  // namespace oai::ngap
