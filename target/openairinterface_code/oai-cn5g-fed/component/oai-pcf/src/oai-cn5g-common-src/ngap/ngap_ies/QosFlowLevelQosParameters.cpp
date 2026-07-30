/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "QosFlowLevelQosParameters.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
QosFlowLevelQosParameters::QosFlowLevelQosParameters() {
  m_GbrQosInformation            = std::nullopt;
  m_ReflectiveQosAttribute       = std::nullopt;
  m_AdditionalQosFlowInformation = std::nullopt;
}

//------------------------------------------------------------------------------
QosFlowLevelQosParameters::~QosFlowLevelQosParameters() {}

//------------------------------------------------------------------------------
void QosFlowLevelQosParameters::set(
    const QosCharacteristics& qosCharacteristics,
    const AllocationAndRetentionPriority& allocationAndRetentionPriority,
    const std::optional<GbrQosFlowInformation>& gbrQosFlowInformation,
    const std::optional<ReflectiveQosAttribute>& reflectiveQosAttribute,
    const std::optional<AdditionalQosFlowInformation>&
        additionalQosFlowInformation) {
  m_QosCharacteristics             = qosCharacteristics;
  m_AllocationAndRetentionPriority = allocationAndRetentionPriority;
  m_GbrQosInformation              = gbrQosFlowInformation;
  m_ReflectiveQosAttribute         = reflectiveQosAttribute;
  m_AdditionalQosFlowInformation   = additionalQosFlowInformation;
}

//------------------------------------------------------------------------------
void QosFlowLevelQosParameters::get(
    QosCharacteristics& qosCharacteristics,
    AllocationAndRetentionPriority& allocationAndRetentionPriority,
    std::optional<GbrQosFlowInformation>& gbrQosFlowInformation,
    std::optional<ReflectiveQosAttribute>& reflectiveQosAttribute,
    std::optional<AdditionalQosFlowInformation>& additionalQosFlowInformation)
    const {
  qosCharacteristics             = m_QosCharacteristics;
  allocationAndRetentionPriority = m_AllocationAndRetentionPriority;
  gbrQosFlowInformation          = m_GbrQosInformation;
  reflectiveQosAttribute         = m_ReflectiveQosAttribute;
  additionalQosFlowInformation   = m_AdditionalQosFlowInformation;
}

//------------------------------------------------------------------------------
bool QosFlowLevelQosParameters::encode(
    Ngap_QosFlowLevelQosParameters_t& qosFlowLevelQosParameters) const {
  if (!m_QosCharacteristics.encode(
          qosFlowLevelQosParameters.qosCharacteristics))
    return false;
  if (!m_AllocationAndRetentionPriority.encode(
          qosFlowLevelQosParameters.allocationAndRetentionPriority))
    return false;

  if (m_GbrQosInformation.has_value()) {
    qosFlowLevelQosParameters.gBR_QosInformation =
        (Ngap_GBR_QosInformation_t*) calloc(
            1, sizeof(Ngap_GBR_QosInformation_t));
    if (!qosFlowLevelQosParameters.gBR_QosInformation) return false;
    if (!m_GbrQosInformation.value().encode(
            *qosFlowLevelQosParameters.gBR_QosInformation))
      return false;
  }

  if (m_ReflectiveQosAttribute.has_value()) {
    qosFlowLevelQosParameters.reflectiveQosAttribute =
        (Ngap_ReflectiveQosAttribute_t*) calloc(
            1, sizeof(Ngap_ReflectiveQosAttribute_t));
    if (!qosFlowLevelQosParameters.reflectiveQosAttribute) return false;
    if (!m_ReflectiveQosAttribute.value().encode(
            *qosFlowLevelQosParameters.reflectiveQosAttribute))
      return false;
  }

  if (m_AdditionalQosFlowInformation.has_value()) {
    qosFlowLevelQosParameters.additionalQosFlowInformation =
        (Ngap_AdditionalQosFlowInformation_t*) calloc(
            1, sizeof(Ngap_AdditionalQosFlowInformation_t));
    if (!qosFlowLevelQosParameters.additionalQosFlowInformation) return false;
    if (!m_AdditionalQosFlowInformation.value().encode(
            *qosFlowLevelQosParameters.additionalQosFlowInformation))
      return false;
  }

  return true;
}

//------------------------------------------------------------------------------
bool QosFlowLevelQosParameters::decode(
    const Ngap_QosFlowLevelQosParameters_t& qosFlowLevelQosParameters) {
  if (!m_QosCharacteristics.decode(
          qosFlowLevelQosParameters.qosCharacteristics))
    return false;
  if (!m_AllocationAndRetentionPriority.decode(
          qosFlowLevelQosParameters.allocationAndRetentionPriority))
    return false;

  if (qosFlowLevelQosParameters.gBR_QosInformation) {
    GbrQosFlowInformation tmp = {};
    if (!tmp.decode(*qosFlowLevelQosParameters.gBR_QosInformation))
      return false;
    m_GbrQosInformation = std::make_optional<GbrQosFlowInformation>(tmp);
  }
  if (qosFlowLevelQosParameters.reflectiveQosAttribute) {
    ReflectiveQosAttribute tmp = {};
    if (!tmp.decode(*qosFlowLevelQosParameters.reflectiveQosAttribute))
      return false;
    m_ReflectiveQosAttribute = std::make_optional<ReflectiveQosAttribute>(tmp);
  }
  if (qosFlowLevelQosParameters.additionalQosFlowInformation) {
    AdditionalQosFlowInformation tmp = {};
    if (!tmp.decode(*qosFlowLevelQosParameters.additionalQosFlowInformation))
      return false;
    m_AdditionalQosFlowInformation =
        std::make_optional<AdditionalQosFlowInformation>(tmp);
  }

  return true;
}
}  // namespace oai::ngap
