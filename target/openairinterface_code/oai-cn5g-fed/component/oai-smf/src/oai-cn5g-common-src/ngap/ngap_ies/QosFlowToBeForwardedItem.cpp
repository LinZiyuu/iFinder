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
void QosFlowToBeForwardedItem::setQosFlowIdentifier(
    const QosFlowIdentifier& qosFlowIdentifier) {
  m_QosFlowIdentifier = qosFlowIdentifier;
}

//------------------------------------------------------------------------------
bool QosFlowToBeForwardedItem::getQosFlowIdentifier(
    QosFlowIdentifier& qosFlowIdentifier) const {
  qosFlowIdentifier = m_QosFlowIdentifier;
  return true;
}

//------------------------------------------------------------------------------
bool QosFlowToBeForwardedItem::encode(
    Ngap_QosFlowToBeForwardedItem_t& item) const {
  if (!m_QosFlowIdentifier.encode(item.qosFlowIdentifier)) {
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool QosFlowToBeForwardedItem::decode(
    const Ngap_QosFlowToBeForwardedItem_t& item) {
  if (!m_QosFlowIdentifier.decode(item.qosFlowIdentifier)) return false;
  return true;
}

}  // namespace oai::ngap
