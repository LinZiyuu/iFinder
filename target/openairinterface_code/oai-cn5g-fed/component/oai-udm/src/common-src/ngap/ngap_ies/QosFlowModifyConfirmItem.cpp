/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "QosFlowModifyConfirmItem.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
QosFlowModifyConfirmItem::QosFlowModifyConfirmItem() {}

//------------------------------------------------------------------------------
QosFlowModifyConfirmItem::~QosFlowModifyConfirmItem() {}

//------------------------------------------------------------------------------
void QosFlowModifyConfirmItem::setQosFlowIdentifier(
    const QosFlowIdentifier& qosFlowIdentifier) {
  m_QosFlowIdentifier = qosFlowIdentifier;
}

//------------------------------------------------------------------------------
void QosFlowModifyConfirmItem::getQosFlowIdentifier(
    QosFlowIdentifier& qosFlowIdentifier) const {
  qosFlowIdentifier = m_QosFlowIdentifier;
}

//------------------------------------------------------------------------------
bool QosFlowModifyConfirmItem::encode(
    Ngap_QosFlowModifyConfirmItem_t& QosFlowModifyConfirmItem) const {
  if (!m_QosFlowIdentifier.encode(QosFlowModifyConfirmItem.qosFlowIdentifier))
    return false;
  return true;
}

//------------------------------------------------------------------------------
bool QosFlowModifyConfirmItem::decode(
    const Ngap_QosFlowModifyConfirmItem_t& QosFlowModifyConfirmItem) {
  if (!m_QosFlowIdentifier.decode(QosFlowModifyConfirmItem.qosFlowIdentifier))
    return false;
  return true;
}
}  // namespace oai::ngap
