/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "QosFlowItemWithDataForwarding.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
QosFlowItemWithDataForWarding::QosFlowItemWithDataForWarding() {
  m_DataForwardingAccepted = std::nullopt;
}

//------------------------------------------------------------------------------
QosFlowItemWithDataForWarding::~QosFlowItemWithDataForWarding() {}

void QosFlowItemWithDataForWarding::set(
    const QosFlowIdentifier& qfi,
    const std::optional<long>& dataForwardingAccepted) {
  m_Qfi                    = qfi;
  m_DataForwardingAccepted = dataForwardingAccepted;
}
//------------------------------------------------------------------------------
void QosFlowItemWithDataForWarding::getQosFlowIdentifier(
    Ngap_QosFlowIdentifier_t& qfi) const {
  long value = {};
  if (m_Qfi.get(value)) {
    qfi = (Ngap_QosFlowIdentifier_t) value;
  }
}

//------------------------------------------------------------------------------
bool QosFlowItemWithDataForWarding::decode(
    const Ngap_QosFlowItemWithDataForwarding_t& qosFlowItem) {
  if (!m_Qfi.decode(qosFlowItem.qosFlowIdentifier)) {
    return false;
  }
  if (qosFlowItem.dataForwardingAccepted)
    m_DataForwardingAccepted =
        std::make_optional<long>(*qosFlowItem.dataForwardingAccepted);
  return true;
}
}  // namespace oai::ngap
