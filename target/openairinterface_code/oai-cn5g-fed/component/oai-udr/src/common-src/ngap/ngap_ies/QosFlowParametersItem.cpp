/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "QosFlowParametersItem.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
QosFlowParametersItem::QosFlowParametersItem() {}

//------------------------------------------------------------------------------
QosFlowParametersItem::~QosFlowParametersItem() {}

//------------------------------------------------------------------------------
void QosFlowParametersItem::setQosFlowIdentifier(
    const QosFlowIdentifier& qosFlowIdentifier) {
  m_QosFlowIdentifier = qosFlowIdentifier;
}

//------------------------------------------------------------------------------
void QosFlowParametersItem::getQosFlowIdentifier(
    QosFlowIdentifier& qosFlowIdentifier) const {
  qosFlowIdentifier = m_QosFlowIdentifier;
}

//------------------------------------------------------------------------------
bool QosFlowParametersItem::encode(
    Ngap_QosFlowParametersItem_t& QosFlowParametersItem) const {
  if (!m_QosFlowIdentifier.encode(QosFlowParametersItem.qosFlowIdentifier))
    return false;

  return true;
}

//------------------------------------------------------------------------------
bool QosFlowParametersItem::decode(
    const Ngap_QosFlowParametersItem_t& QosFlowParametersItem) {
  if (!m_QosFlowIdentifier.decode(QosFlowParametersItem.qosFlowIdentifier))
    return false;

  return true;
}
}  // namespace oai::ngap
