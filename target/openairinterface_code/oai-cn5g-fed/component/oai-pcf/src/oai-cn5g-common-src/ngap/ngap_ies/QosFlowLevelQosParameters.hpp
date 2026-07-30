/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _QOS_FLOW_LEVEL_QOS_PARAMETERS_H_
#define _QOS_FLOW_LEVEL_QOS_PARAMETERS_H_

#include "AdditionalQosFlowInformation.hpp"
#include "AllocationAndRetentionPriority.hpp"
#include "GbrQosFlowInformation.hpp"
#include "QosCharacteristics.hpp"
#include "ReflectiveQosAttribute.hpp"

extern "C" {
#include "Ngap_QosFlowLevelQosParameters.h"
}

namespace oai::ngap {

class QosFlowLevelQosParameters {
 public:
  QosFlowLevelQosParameters();
  virtual ~QosFlowLevelQosParameters();

  void set(
      const QosCharacteristics& qosCharacteristics,
      const AllocationAndRetentionPriority& allocationAndRetentionPriority,
      const std::optional<GbrQosFlowInformation>& gbrQosFlowInformation =
          std::nullopt,
      const std::optional<ReflectiveQosAttribute>& reflectiveQosAttribute =
          std::nullopt,
      const std::optional<AdditionalQosFlowInformation>&
          additionalQosFlowInformation = std::nullopt);

  void get(
      QosCharacteristics& qosCharacteristics,
      AllocationAndRetentionPriority& allocationAndRetentionPriority,
      std::optional<GbrQosFlowInformation>& gbrQosFlowInformation,
      std::optional<ReflectiveQosAttribute>& reflectiveQosAttribute,
      std::optional<AdditionalQosFlowInformation>& additionalQosFlowInformation)
      const;

  bool encode(Ngap_QosFlowLevelQosParameters_t&) const;
  bool decode(const Ngap_QosFlowLevelQosParameters_t&);

 private:
  QosCharacteristics m_QosCharacteristics;                          // Mandatory
  AllocationAndRetentionPriority m_AllocationAndRetentionPriority;  // Mandatory
  std::optional<GbrQosFlowInformation> m_GbrQosInformation;         // Optional
  std::optional<ReflectiveQosAttribute> m_ReflectiveQosAttribute;   // Optional
  std::optional<AdditionalQosFlowInformation>
      m_AdditionalQosFlowInformation;  // Optional
};

}  // namespace oai::ngap

#endif
