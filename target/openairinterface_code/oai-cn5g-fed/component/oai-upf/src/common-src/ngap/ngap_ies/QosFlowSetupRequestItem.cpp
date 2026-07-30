/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "QosFlowSetupRequestItem.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
QosFlowSetupRequestItem::QosFlowSetupRequestItem() {}

//------------------------------------------------------------------------------
QosFlowSetupRequestItem::~QosFlowSetupRequestItem() {}

//------------------------------------------------------------------------------
void QosFlowSetupRequestItem::set(
    const QosFlowIdentifier& qosFlowIdentifier,
    const QosFlowLevelQosParameters& qosFlowLevelQosParameters) {
  m_QosFlowIdentifier         = qosFlowIdentifier;
  m_QosFlowLevelQosParameters = qosFlowLevelQosParameters;
}

//------------------------------------------------------------------------------
bool QosFlowSetupRequestItem::get(
    QosFlowIdentifier& qosFlowIdentifier,
    QosFlowLevelQosParameters& qosFlowLevelQosParameters) const {
  qosFlowIdentifier         = m_QosFlowIdentifier;
  qosFlowLevelQosParameters = m_QosFlowLevelQosParameters;

  return true;
}

//------------------------------------------------------------------------------
bool QosFlowSetupRequestItem::encode(
    Ngap_QosFlowSetupRequestItem_t& qosFlowSetupRequestItem) const {
  if (!m_QosFlowIdentifier.encode(qosFlowSetupRequestItem.qosFlowIdentifier))
    return false;
  if (!m_QosFlowLevelQosParameters.encode(
          qosFlowSetupRequestItem.qosFlowLevelQosParameters))
    return false;

  return true;
}

//------------------------------------------------------------------------------
bool QosFlowSetupRequestItem::decode(
    const Ngap_QosFlowSetupRequestItem_t& qosFlowSetupRequestItem) {
  if (!m_QosFlowIdentifier.decode(qosFlowSetupRequestItem.qosFlowIdentifier))
    return false;
  if (!m_QosFlowLevelQosParameters.decode(
          qosFlowSetupRequestItem.qosFlowLevelQosParameters))
    return false;

  return true;
}
}  // namespace oai::ngap
