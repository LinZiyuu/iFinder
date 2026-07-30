/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "QosFlowSetupRequestItem.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
QosFlowIdentifier::QosFlowIdentifier() {
  m_QosFlowIdentifier = 0;
}

//------------------------------------------------------------------------------
QosFlowIdentifier::~QosFlowIdentifier() {}

//------------------------------------------------------------------------------
void QosFlowIdentifier::set(const long& value) {
  m_QosFlowIdentifier = value;
}

//------------------------------------------------------------------------------
void QosFlowIdentifier::get(long& value) const {
  value = m_QosFlowIdentifier;
}

//------------------------------------------------------------------------------
long QosFlowIdentifier::get() const {
  return m_QosFlowIdentifier;
}

//------------------------------------------------------------------------------
bool QosFlowIdentifier::encode(
    Ngap_QosFlowIdentifier_t& qosFlowIdentifier) const {
  qosFlowIdentifier = m_QosFlowIdentifier;

  return true;
}

//------------------------------------------------------------------------------
bool QosFlowIdentifier::decode(
    const Ngap_QosFlowIdentifier_t& qosFlowIdentifier) {
  m_QosFlowIdentifier = qosFlowIdentifier;

  return true;
}
}  // namespace oai::ngap
