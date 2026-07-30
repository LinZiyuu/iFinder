/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "AssociatedQosFlowItem.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
AssociatedQosFlowItem::AssociatedQosFlowItem() {
  m_QosFlowMappingIndication = -1;
}

//------------------------------------------------------------------------------
AssociatedQosFlowItem::~AssociatedQosFlowItem() {}

//------------------------------------------------------------------------------
void AssociatedQosFlowItem::set(
    const e_Ngap_AssociatedQosFlowItem__qosFlowMappingIndication&
        qosFlowMappingIndication,
    const QosFlowIdentifier& qosFlowIdentifier) {
  m_QosFlowMappingIndication = qosFlowMappingIndication;
  m_QosFlowIdentifier        = qosFlowIdentifier;
}

//------------------------------------------------------------------------------
void AssociatedQosFlowItem::set(const QosFlowIdentifier& qosFlowIdentifier) {
  m_QosFlowIdentifier = qosFlowIdentifier;
}

//------------------------------------------------------------------------------
void AssociatedQosFlowItem::get(QosFlowIdentifier& qosFlowIdentifier) const {
  qosFlowIdentifier = m_QosFlowIdentifier;
}

//------------------------------------------------------------------------------
bool AssociatedQosFlowItem::get(
    long& qosFlowMappingIndication,
    QosFlowIdentifier& qosFlowIdentifier) const {
  qosFlowMappingIndication = m_QosFlowMappingIndication;
  qosFlowIdentifier        = m_QosFlowIdentifier;

  return true;
}

//------------------------------------------------------------------------------
bool AssociatedQosFlowItem::encode(
    Ngap_AssociatedQosFlowItem_t& associatedQosFlowItem) const {
  if (m_QosFlowMappingIndication >= 0) {
    associatedQosFlowItem.qosFlowMappingIndication =
        (long*) calloc(1, sizeof(long));
    *associatedQosFlowItem.qosFlowMappingIndication =
        m_QosFlowMappingIndication;
  }

  if (!m_QosFlowIdentifier.encode(associatedQosFlowItem.qosFlowIdentifier))
    return false;

  return true;
}

//------------------------------------------------------------------------------
bool AssociatedQosFlowItem::decode(
    const Ngap_AssociatedQosFlowItem_t& associatedQosFlowItem) {
  if (!m_QosFlowIdentifier.decode(associatedQosFlowItem.qosFlowIdentifier))
    return false;

  if (associatedQosFlowItem.qosFlowMappingIndication) {
    m_QosFlowMappingIndication =
        *associatedQosFlowItem.qosFlowMappingIndication;
  }

  return true;
}

}  // namespace oai::ngap
