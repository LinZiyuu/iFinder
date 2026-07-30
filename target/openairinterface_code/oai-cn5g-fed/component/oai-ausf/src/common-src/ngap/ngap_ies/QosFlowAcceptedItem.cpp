/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "QosFlowAcceptedItem.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
QosFlowAcceptedItem::QosFlowAcceptedItem() {}

//------------------------------------------------------------------------------
QosFlowAcceptedItem::~QosFlowAcceptedItem() {}

//------------------------------------------------------------------------------
void QosFlowAcceptedItem::setQosFlowIdentifier(
    const QosFlowIdentifier& qosFlowIdentifier) {
  m_QosFlowIdentifier = qosFlowIdentifier;
}

//------------------------------------------------------------------------------
void QosFlowAcceptedItem::getQosFlowIdentifier(
    QosFlowIdentifier& qosFlowIdentifier) const {
  qosFlowIdentifier = m_QosFlowIdentifier;
}

/*
//------------------------------------------------------------------------------
void QosFlowAcceptedItem::setCurrentQoSParametersSetIndex(uint32_t&
          currentQoSParametersSetIndex) {
        m_CurrentQoSParametersSetIndex =
std::make_optional<uint32_t>(currentQoSParametersSetIndex);
}
//------------------------------------------------------------------------------
void
QosFlowAcceptedItem::getCurrentQoSParametersSetIndex(std::optional<uint32_t>&
                  currentQoSParametersSetIndex) const{
        m_CurrentQoSParametersSetIndex = currentQoSParametersSetIndex;
}
*/

//------------------------------------------------------------------------------
bool QosFlowAcceptedItem::encode(
    Ngap_QosFlowAcceptedItem_t& QosFlowAcceptedItem) const {
  if (!m_QosFlowIdentifier.encode(QosFlowAcceptedItem.qosFlowIdentifier))
    return false;

  return true;
}

//------------------------------------------------------------------------------
bool QosFlowAcceptedItem::decode(
    const Ngap_QosFlowAcceptedItem_t& QosFlowAcceptedItem) {
  if (!m_QosFlowIdentifier.decode(QosFlowAcceptedItem.qosFlowIdentifier))
    return false;

  return true;
}
}  // namespace oai::ngap
