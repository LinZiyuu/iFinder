/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _QOS_FLOW_FEEDBACK_ITEM_H_
#define _QOS_FLOW_FEEDBACK_ITEM_H_

#include "QosFlowIdentifier.hpp"

extern "C" {
#include "Ngap_QosFlowFeedbackItem.h"
}

namespace oai::ngap {

class QosFlowFeedbackItem {
 public:
  QosFlowFeedbackItem();
  virtual ~QosFlowFeedbackItem();

  void setQosFlowIdentifier(const QosFlowIdentifier& qosFlowIdentifier);
  bool getQosFlowIdentifier(QosFlowIdentifier& qosFlowIdentifier) const;

  bool encode(Ngap_QosFlowFeedbackItem_t&) const;
  bool decode(const Ngap_QosFlowFeedbackItem_t&);

 private:
  QosFlowIdentifier m_QosFlowIdentifier;  // Mandatory
  // TODO: Update Feedback (Optional)
  // TODO: CN Packet Delay Budget Downlink (Optional)
  // TODO: CN Packet Delay Budget Uplink (Optional)
};

}  // namespace oai::ngap

#endif
