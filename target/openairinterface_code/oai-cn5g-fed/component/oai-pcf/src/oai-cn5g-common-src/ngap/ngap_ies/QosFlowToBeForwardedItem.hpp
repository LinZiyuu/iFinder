/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _QOS_FLOW_TO_BE_FORWARDED_ITEM_H_
#define _QOS_FLOW_TO_BE_FORWARDED_ITEM_H_

#include "QosFlowIdentifier.hpp"

extern "C" {
#include "Ngap_QosFlowToBeForwardedItem.h"
}

namespace oai::ngap {
class QosFlowToBeForwardedItem {
 public:
  QosFlowToBeForwardedItem();
  virtual ~QosFlowToBeForwardedItem();

  void setQosFlowIdentifier(const QosFlowIdentifier& qosFlowIdentifier);
  bool getQosFlowIdentifier(QosFlowIdentifier& qosFlowIdentifier) const;

  // TODO: Get

  bool encode(Ngap_QosFlowToBeForwardedItem_t& item) const;
  bool decode(const Ngap_QosFlowToBeForwardedItem_t& item);
  // TODO: decode

 private:
  QosFlowIdentifier m_QosFlowIdentifier;  // Mandatory
};
}  // namespace oai::ngap
#endif
