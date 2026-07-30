/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "QosFlowAddOrModifyResponseItem.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
QosFlowAddOrModifyResponseItem::QosFlowAddOrModifyResponseItem() {}

//------------------------------------------------------------------------------
QosFlowAddOrModifyResponseItem::~QosFlowAddOrModifyResponseItem() {}

//------------------------------------------------------------------------------
void QosFlowAddOrModifyResponseItem::setQosFlowIdentifier(
    const QosFlowIdentifier& qosFlowIdentifier) {
  m_QosFlowIdentifier = qosFlowIdentifier;
}

//------------------------------------------------------------------------------
void QosFlowAddOrModifyResponseItem::getQosFlowIdentifier(
    QosFlowIdentifier& qosFlowIdentifier) const {
  qosFlowIdentifier = m_QosFlowIdentifier;
}

/*
//------------------------------------------------------------------------------
void QosFlowAddOrModifyResponseItem::setCurrentQoSParametersSetIndex(uint32_t&
          currentQoSParametersSetIndex) {
        m_CurrentQoSParametersSetIndex =
std::make_optional<uint32_t>(currentQoSParametersSetIndex);
}
//------------------------------------------------------------------------------
void
QosFlowAddOrModifyResponseItem::getCurrentQoSParametersSetIndex(std::optional<uint32_t>&
                  currentQoSParametersSetIndex) const{
        m_CurrentQoSParametersSetIndex = currentQoSParametersSetIndex;
}
*/

//------------------------------------------------------------------------------
bool QosFlowAddOrModifyResponseItem::encode(
    Ngap_QosFlowAddOrModifyResponseItem_t& QosFlowAddOrModifyResponseItem)
    const {
  if (!m_QosFlowIdentifier.encode(
          QosFlowAddOrModifyResponseItem.qosFlowIdentifier))
    return false;

  return true;
}

//------------------------------------------------------------------------------
bool QosFlowAddOrModifyResponseItem::decode(
    const Ngap_QosFlowAddOrModifyResponseItem_t&
        QosFlowAddOrModifyResponseItem) {
  if (!m_QosFlowIdentifier.decode(
          QosFlowAddOrModifyResponseItem.qosFlowIdentifier))
    return false;

  return true;
}
}  // namespace oai::ngap
