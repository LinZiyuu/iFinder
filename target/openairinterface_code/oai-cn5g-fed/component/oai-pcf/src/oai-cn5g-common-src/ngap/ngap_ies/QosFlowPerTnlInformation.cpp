/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "QosFlowPerTnlInformation.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
QosFlowPerTnlInformation::QosFlowPerTnlInformation() {}

//------------------------------------------------------------------------------
QosFlowPerTnlInformation::~QosFlowPerTnlInformation() {}

//------------------------------------------------------------------------------
void QosFlowPerTnlInformation::set(
    const UpTransportLayerInformation& uPTransportLayerInformation,
    const AssociatedQosFlowList& associatedQosFlowList) {
  m_UpTransportLayerInformation = uPTransportLayerInformation;
  m_AssociatedQosFlowList       = associatedQosFlowList;
}

//------------------------------------------------------------------------------
void QosFlowPerTnlInformation::get(
    UpTransportLayerInformation& uPTransportLayerInformation,
    AssociatedQosFlowList& associatedQosFlowList) const {
  uPTransportLayerInformation = m_UpTransportLayerInformation;
  associatedQosFlowList       = m_AssociatedQosFlowList;
}

//------------------------------------------------------------------------------
bool QosFlowPerTnlInformation::encode(
    Ngap_QosFlowPerTNLInformation_t& qosFlowPerTnlInformation) const {
  if (!m_UpTransportLayerInformation.encode(
          qosFlowPerTnlInformation.uPTransportLayerInformation))
    return false;

  if (!m_AssociatedQosFlowList.encode(
          qosFlowPerTnlInformation.associatedQosFlowList))
    return false;

  return true;
}

//------------------------------------------------------------------------------
bool QosFlowPerTnlInformation::decode(
    const Ngap_QosFlowPerTNLInformation_t& qosFlowPerTnlInformation) {
  if (!m_UpTransportLayerInformation.decode(
          qosFlowPerTnlInformation.uPTransportLayerInformation))
    return false;
  if (!m_AssociatedQosFlowList.decode(
          qosFlowPerTnlInformation.associatedQosFlowList))
    return false;

  return true;
}

}  // namespace oai::ngap
