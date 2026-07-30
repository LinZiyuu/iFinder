/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "QosFlowItemWithDataForwarding.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
QosFlowItemWithDataForwarding::QosFlowItemWithDataForwarding() {
  m_DataForwardingAccepted = std::nullopt;
}

//------------------------------------------------------------------------------
QosFlowItemWithDataForwarding::~QosFlowItemWithDataForwarding() {}

//------------------------------------------------------------------------------
void QosFlowItemWithDataForwarding::set(
    const QosFlowIdentifier& qosFlowIdentifier,
    const std::optional<long>& dataForwardingAccepted) {
  m_QosFlowIdentifier      = qosFlowIdentifier;
  m_DataForwardingAccepted = dataForwardingAccepted;
}

//------------------------------------------------------------------------------
void QosFlowItemWithDataForwarding::setQosFlowIdentifier(
    const QosFlowIdentifier& qosFlowIdentifier) {
  m_QosFlowIdentifier = qosFlowIdentifier;
}

//------------------------------------------------------------------------------
void QosFlowItemWithDataForwarding::getQosFlowIdentifier(
    QosFlowIdentifier& qosFlowIdentifier) const {
  qosFlowIdentifier = m_QosFlowIdentifier;
}

//------------------------------------------------------------------------------
void QosFlowItemWithDataForwarding::setDataForwardingAccepted(
    long dataForwardingAccepted) {
  m_DataForwardingAccepted = std::make_optional<long>(dataForwardingAccepted);
}

//------------------------------------------------------------------------------
void QosFlowItemWithDataForwarding::getDataForwardingAccepted(
    std::optional<long>& dataForwardingAccepted) const {
  dataForwardingAccepted = m_DataForwardingAccepted;
}
//------------------------------------------------------------------------------
bool QosFlowItemWithDataForwarding::encode(
    Ngap_QosFlowItemWithDataForwarding_t& item) const {
  if (!m_QosFlowIdentifier.encode(item.qosFlowIdentifier)) return false;
  if (m_DataForwardingAccepted.has_value()) {
    item.dataForwardingAccepted  = (long*) calloc(1, sizeof(long));
    *item.dataForwardingAccepted = m_DataForwardingAccepted.value();
  }

  return true;
}

//------------------------------------------------------------------------------
bool QosFlowItemWithDataForwarding::decode(
    const Ngap_QosFlowItemWithDataForwarding_t& item) {
  if (!m_QosFlowIdentifier.decode(item.qosFlowIdentifier)) {
    return false;
  }
  if (item.dataForwardingAccepted)
    m_DataForwardingAccepted =
        std::make_optional<long>(*item.dataForwardingAccepted);
  return true;
}
}  // namespace oai::ngap
