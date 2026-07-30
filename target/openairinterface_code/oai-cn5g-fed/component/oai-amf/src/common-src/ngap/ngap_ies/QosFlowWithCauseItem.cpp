/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "QosFlowWithCauseItem.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
QosFlowWithCauseItem::QosFlowWithCauseItem() {}

//------------------------------------------------------------------------------
QosFlowWithCauseItem::~QosFlowWithCauseItem() {}

//------------------------------------------------------------------------------
void QosFlowWithCauseItem::set(
    const QosFlowIdentifier& qosFlowIdentifier, const Cause& cause) {
  m_QosFlowIdentifier = qosFlowIdentifier;
  m_Cause             = cause;
}

//------------------------------------------------------------------------------
bool QosFlowWithCauseItem::get(
    QosFlowIdentifier& qosFlowIdentifier, Cause& cause) const {
  qosFlowIdentifier = m_QosFlowIdentifier;
  cause             = m_Cause;

  return true;
}

//------------------------------------------------------------------------------
void QosFlowWithCauseItem::setQosFlowIdentifier(
    const QosFlowIdentifier& qosFlowIdentifier) {
  m_QosFlowIdentifier = qosFlowIdentifier;
}

//------------------------------------------------------------------------------
bool QosFlowWithCauseItem::getQosFlowIdentifier(
    QosFlowIdentifier& qosFlowIdentifier) const {
  qosFlowIdentifier = m_QosFlowIdentifier;
  return true;
}

//------------------------------------------------------------------------------
void QosFlowWithCauseItem::setCause(const Cause& cause) {
  m_Cause = cause;
}

//------------------------------------------------------------------------------
bool QosFlowWithCauseItem::getCause(Cause& cause) const {
  cause = m_Cause;

  return true;
}

//------------------------------------------------------------------------------
bool QosFlowWithCauseItem::encode(
    Ngap_QosFlowWithCauseItem_t& QosFlowWithCauseItem) const {
  if (!m_QosFlowIdentifier.encode(QosFlowWithCauseItem.qosFlowIdentifier))
    return false;
  if (!m_Cause.encode(QosFlowWithCauseItem.cause)) return false;

  return true;
}

//------------------------------------------------------------------------------
bool QosFlowWithCauseItem::decode(
    const Ngap_QosFlowWithCauseItem_t& QosFlowWithCauseItem) {
  if (!m_QosFlowIdentifier.decode(QosFlowWithCauseItem.qosFlowIdentifier))
    return false;
  if (!m_Cause.decode(QosFlowWithCauseItem.cause)) return false;

  return true;
}
}  // namespace oai::ngap
