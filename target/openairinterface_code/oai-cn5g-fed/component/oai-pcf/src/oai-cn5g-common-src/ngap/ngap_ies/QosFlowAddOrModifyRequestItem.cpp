/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "QosFlowAddOrModifyRequestItem.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
QosFlowAddOrModifyRequestItem::QosFlowAddOrModifyRequestItem() {}

//------------------------------------------------------------------------------
QosFlowAddOrModifyRequestItem::~QosFlowAddOrModifyRequestItem() {}

//------------------------------------------------------------------------------
void QosFlowAddOrModifyRequestItem::setQosFlowIdentifier(
    const QosFlowIdentifier& qosFlowIdentifier) {
  m_QosFlowIdentifier = qosFlowIdentifier;
}

//------------------------------------------------------------------------------
void QosFlowAddOrModifyRequestItem::getQosFlowIdentifier(
    QosFlowIdentifier& qosFlowIdentifier) const {
  qosFlowIdentifier = m_QosFlowIdentifier;
}

//------------------------------------------------------------------------------
void QosFlowAddOrModifyRequestItem::setQosFlowLevelQosParameters(
    const QosFlowLevelQosParameters& qosFlowLevelQosParameters) {
  m_QosFlowLevelQosParameters =
      std::make_optional<QosFlowLevelQosParameters>(qosFlowLevelQosParameters);
}

//------------------------------------------------------------------------------
void QosFlowAddOrModifyRequestItem::setQosFlowLevelQosParameters(
    const std::optional<QosFlowLevelQosParameters>& qosFlowLevelQosParameters) {
  m_QosFlowLevelQosParameters = qosFlowLevelQosParameters;
}

//------------------------------------------------------------------------------
void QosFlowAddOrModifyRequestItem::setQosFlowLevelQosParameters(
    std::optional<QosFlowLevelQosParameters>& qosFlowLevelQosParameters) const {
  qosFlowLevelQosParameters = m_QosFlowLevelQosParameters;
}

//------------------------------------------------------------------------------
bool QosFlowAddOrModifyRequestItem::encode(
    Ngap_QosFlowAddOrModifyRequestItem_t& QosFlowAddOrModifyRequestItem) const {
  if (!m_QosFlowIdentifier.encode(
          QosFlowAddOrModifyRequestItem.qosFlowIdentifier))
    return false;
  if (m_QosFlowLevelQosParameters.has_value()) {
    QosFlowAddOrModifyRequestItem.qosFlowLevelQosParameters =
        (Ngap_QosFlowLevelQosParameters_t*) calloc(
            1, sizeof(Ngap_QosFlowLevelQosParameters_t));
    if (!m_QosFlowLevelQosParameters.value().encode(
            *QosFlowAddOrModifyRequestItem.qosFlowLevelQosParameters))
      return false;
  }

  return true;
}

//------------------------------------------------------------------------------
bool QosFlowAddOrModifyRequestItem::decode(
    const Ngap_QosFlowAddOrModifyRequestItem_t& QosFlowAddOrModifyRequestItem) {
  if (!m_QosFlowIdentifier.decode(
          QosFlowAddOrModifyRequestItem.qosFlowIdentifier))
    return false;
  if (QosFlowAddOrModifyRequestItem.qosFlowLevelQosParameters) {
    QosFlowLevelQosParameters qosFlowLevelQosParameters = {};
    if (!qosFlowLevelQosParameters.decode(
            *QosFlowAddOrModifyRequestItem.qosFlowLevelQosParameters))
      return false;
    m_QosFlowLevelQosParameters = std::make_optional<QosFlowLevelQosParameters>(
        qosFlowLevelQosParameters);
  }

  return true;
}
}  // namespace oai::ngap
