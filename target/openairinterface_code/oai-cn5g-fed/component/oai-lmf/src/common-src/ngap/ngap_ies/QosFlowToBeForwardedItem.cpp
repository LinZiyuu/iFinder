/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "QosFlowToBeForwardedItem.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
QosFlowToBeForwardedItem::QosFlowToBeForwardedItem() {}

//------------------------------------------------------------------------------
QosFlowToBeForwardedItem::~QosFlowToBeForwardedItem() {}

//------------------------------------------------------------------------------
void QosFlowToBeForwardedItem::set(const QosFlowIdentifier& qfi) {
  m_Qfi = qfi;
}

//------------------------------------------------------------------------------
bool QosFlowToBeForwardedItem::encode(
    Ngap_QosFlowToBeForwardedItem_t& qosFlowItem) const {
  if (!m_Qfi.encode(qosFlowItem.qosFlowIdentifier)) {
    return false;
  }
  return true;
}
}  // namespace oai::ngap
