/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _QOS_FLOW_ADD_OR_MODIFY_REQUEST_ITEM_H_
#define _QOS_FLOW_ADD_OR_MODIFY_REQUEST_ITEM_H_

#include "QosFlowIdentifier.hpp"
#include "QosFlowLevelQosParameters.hpp"

extern "C" {
#include "Ngap_QosFlowAddOrModifyRequestItem.h"
}

namespace oai::ngap {

class QosFlowAddOrModifyRequestItem {
 public:
  QosFlowAddOrModifyRequestItem();
  virtual ~QosFlowAddOrModifyRequestItem();

  void setQosFlowIdentifier(const QosFlowIdentifier& qosFlowIdentifier);
  void getQosFlowIdentifier(QosFlowIdentifier& qosFlowIdentifier) const;

  void setQosFlowLevelQosParameters(
      const QosFlowLevelQosParameters& qosFlowLevelQosParameters);
  void setQosFlowLevelQosParameters(
      const std::optional<QosFlowLevelQosParameters>&
          qosFlowLevelQosParameters);
  void setQosFlowLevelQosParameters(std::optional<QosFlowLevelQosParameters>&
                                        qosFlowLevelQosParameters) const;

  bool encode(Ngap_QosFlowAddOrModifyRequestItem_t&) const;
  bool decode(const Ngap_QosFlowAddOrModifyRequestItem_t&);

 private:
  QosFlowIdentifier m_QosFlowIdentifier;  // Mandatory
  std::optional<QosFlowLevelQosParameters>
      m_QosFlowLevelQosParameters;  // Optional
  // TODO: E-RAB ID (Optional)
  // TODO: TSC Traffic Characteristics
  // TODO: Redundant QoS Flow Indicator
};

}  // namespace oai::ngap

#endif
