/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "AdditionalQosFlowInformation.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
AdditionalQosFlowInformation::AdditionalQosFlowInformation() {
  m_QosFlowInfo = 0;
}

//------------------------------------------------------------------------------
AdditionalQosFlowInformation::AdditionalQosFlowInformation(
    e_Ngap_AdditionalQosFlowInformation value) {
  m_QosFlowInfo = value;
}
//------------------------------------------------------------------------------
AdditionalQosFlowInformation::~AdditionalQosFlowInformation() {}

//------------------------------------------------------------------------------
void AdditionalQosFlowInformation::set(
    e_Ngap_AdditionalQosFlowInformation value) {
  m_QosFlowInfo = value;
}

//------------------------------------------------------------------------------
bool AdditionalQosFlowInformation::get(
    e_Ngap_AdditionalQosFlowInformation& value) const {
  if (m_QosFlowInfo == Ngap_AdditionalQosFlowInformation_more_likely)
    value = (e_Ngap_AdditionalQosFlowInformation) m_QosFlowInfo;
  else
    return false;

  return true;
}

//------------------------------------------------------------------------------
bool AdditionalQosFlowInformation::encode(
    Ngap_AdditionalQosFlowInformation_t& value) const {
  value = m_QosFlowInfo;

  return true;
}

//------------------------------------------------------------------------------
bool AdditionalQosFlowInformation::decode(
    const Ngap_AdditionalQosFlowInformation_t& value) {
  m_QosFlowInfo = value;

  return true;
}
}  // namespace oai::ngap
