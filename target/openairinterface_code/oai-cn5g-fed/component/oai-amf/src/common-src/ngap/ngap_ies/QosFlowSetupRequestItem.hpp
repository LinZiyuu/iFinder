/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _QOS_FLOW_SETUP_REQUEST_ITEM_H_
#define _QOS_FLOW_SETUP_REQUEST_ITEM_H_

#include "QosFlowIdentifier.hpp"
#include "QosFlowLevelQosParameters.hpp"

extern "C" {
#include "Ngap_QosFlowSetupRequestItem.h"
}

namespace oai::ngap {

class QosFlowSetupRequestItem {
 public:
  QosFlowSetupRequestItem();
  virtual ~QosFlowSetupRequestItem();

  void set(
      const QosFlowIdentifier& qosFlowIdentifier,
      const QosFlowLevelQosParameters& qosFlowLevelQosParameters);
  bool get(
      QosFlowIdentifier& qosFlowIdentifier,
      QosFlowLevelQosParameters& qosFlowLevelQosParameters) const;

  bool encode(Ngap_QosFlowSetupRequestItem_t&) const;
  bool decode(const Ngap_QosFlowSetupRequestItem_t&);

 private:
  QosFlowIdentifier m_QosFlowIdentifier;                  // Mandatory
  QosFlowLevelQosParameters m_QosFlowLevelQosParameters;  // Mandatory
  // TODO: E-RAB ID //Optional
};

}  // namespace oai::ngap

#endif
