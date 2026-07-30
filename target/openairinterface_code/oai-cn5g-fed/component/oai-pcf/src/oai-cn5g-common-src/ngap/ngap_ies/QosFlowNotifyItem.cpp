/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "QosFlowNotifyItem.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
QosFlowNotifyItem::QosFlowNotifyItem() {}

//------------------------------------------------------------------------------
QosFlowNotifyItem::~QosFlowNotifyItem() {}

//------------------------------------------------------------------------------
void QosFlowNotifyItem::setQosFlowIdentifier(
    const QosFlowIdentifier& qosFlowIdentifier) {
  m_QosFlowIdentifier = qosFlowIdentifier;
}

//------------------------------------------------------------------------------
void QosFlowNotifyItem::getQosFlowIdentifier(
    QosFlowIdentifier& qosFlowIdentifier) const {
  qosFlowIdentifier = m_QosFlowIdentifier;
}

//------------------------------------------------------------------------------
void QosFlowNotifyItem::setNotificationCause(
    const NotificationCause& notificationCause) {
  m_NotificationCause = notificationCause;
}

//------------------------------------------------------------------------------
void QosFlowNotifyItem::getNotificationCause(
    NotificationCause& notificationCause) const {
  notificationCause = m_NotificationCause;
}

/*
//------------------------------------------------------------------------------
void QosFlowNotifyItem::setCurrentQoSParametersSetIndex(uint32_t&
          currentQoSParametersSetIndex) {
        m_CurrentQoSParametersSetIndex =
std::make_optional<uint32_t>(currentQoSParametersSetIndex);
}
//------------------------------------------------------------------------------
void
QosFlowNotifyItem::getCurrentQoSParametersSetIndex(std::optional<uint32_t>&
                  currentQoSParametersSetIndex) const{
        m_CurrentQoSParametersSetIndex = currentQoSParametersSetIndex;
}
*/

//------------------------------------------------------------------------------
bool QosFlowNotifyItem::encode(
    Ngap_QosFlowNotifyItem_t& QosFlowNotifyItem) const {
  if (!m_QosFlowIdentifier.encode(QosFlowNotifyItem.qosFlowIdentifier))
    return false;

  if (!m_NotificationCause.encode(QosFlowNotifyItem.notificationCause))
    return false;

  return true;
}

//------------------------------------------------------------------------------
bool QosFlowNotifyItem::decode(
    const Ngap_QosFlowNotifyItem_t& QosFlowNotifyItem) {
  if (!m_QosFlowIdentifier.decode(QosFlowNotifyItem.qosFlowIdentifier))
    return false;

  if (!m_NotificationCause.decode(QosFlowNotifyItem.notificationCause))
    return false;

  return true;
}
}  // namespace oai::ngap
