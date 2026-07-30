/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _ASSOCIATED_QOS_FLOW_ITEM_H_
#define _ASSOCIATED_QOS_FLOW_ITEM_H_

#include "QosFlowIdentifier.hpp"

extern "C" {
#include "Ngap_AssociatedQosFlowItem.h"
}

namespace oai::ngap {

class AssociatedQosFlowItem {
 public:
  AssociatedQosFlowItem();
  virtual ~AssociatedQosFlowItem();

  void set(
      const e_Ngap_AssociatedQosFlowItem__qosFlowMappingIndication&
          qosFlowMappingIndication,
      const QosFlowIdentifier& qosFlowIdentifier);
  bool get(long& qosFlowMappingIndication, QosFlowIdentifier& qosFlowIdentifier)
      const;

  void set(const QosFlowIdentifier& qosFlowIdentifier);
  void get(QosFlowIdentifier& qosFlowIdentifier) const;

  bool encode(Ngap_AssociatedQosFlowItem_t& associatedQosFlowItem) const;
  bool decode(const Ngap_AssociatedQosFlowItem_t& associatedQosFlowItem);

 private:
  QosFlowIdentifier m_QosFlowIdentifier;  // Mandatory
  long m_QosFlowMappingIndication;        // TODO: Optional
};

}  // namespace oai::ngap

#endif
