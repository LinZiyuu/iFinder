/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _QOS_FLOW_PARAMETERS_ITEM_H_
#define _QOS_FLOW_PARAMETERS_ITEM_H_

#include "QosFlowIdentifier.hpp"

extern "C" {
#include "Ngap_QosFlowParametersItem.h"
}

namespace oai::ngap {

class QosFlowParametersItem {
 public:
  QosFlowParametersItem();
  virtual ~QosFlowParametersItem();

  void setQosFlowIdentifier(const QosFlowIdentifier& qosFlowIdentifier);
  void getQosFlowIdentifier(QosFlowIdentifier& qosFlowIdentifier) const;
  bool encode(Ngap_QosFlowParametersItem_t&) const;
  bool decode(const Ngap_QosFlowParametersItem_t&);

 private:
  QosFlowIdentifier m_QosFlowIdentifier;  // Mandatory
  // TODO: Alternative QoS Parameters Set List (Optional)
  // TODO:  CN Packet Delay Budget Downlink (Optional)
  // TODO:  CN Packet Delay Budget Uplink (Optional)
  // TODO: Burst Arrival Time Downlink (Optional)
};

}  // namespace oai::ngap

#endif
