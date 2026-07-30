/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "QosFlowFeedbackItem.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
QosFlowFeedbackItem::QosFlowFeedbackItem() {}

//------------------------------------------------------------------------------
QosFlowFeedbackItem::~QosFlowFeedbackItem() {}

//------------------------------------------------------------------------------
void QosFlowFeedbackItem::setQosFlowIdentifier(
    const QosFlowIdentifier& qosFlowIdentifier) {
  m_QosFlowIdentifier = qosFlowIdentifier;
}

//------------------------------------------------------------------------------
bool QosFlowFeedbackItem::getQosFlowIdentifier(
    QosFlowIdentifier& qosFlowIdentifier) const {
  qosFlowIdentifier = m_QosFlowIdentifier;
  return true;
}

//------------------------------------------------------------------------------
bool QosFlowFeedbackItem::encode(
    Ngap_QosFlowFeedbackItem_t& QosFlowFeedbackItem) const {
  if (!m_QosFlowIdentifier.encode(QosFlowFeedbackItem.qosFlowIdentifier))
    return false;

  return true;
}

//------------------------------------------------------------------------------
bool QosFlowFeedbackItem::decode(
    const Ngap_QosFlowFeedbackItem_t& QosFlowFeedbackItem) {
  if (!m_QosFlowIdentifier.decode(QosFlowFeedbackItem.qosFlowIdentifier))
    return false;

  return true;
}
}  // namespace oai::ngap
