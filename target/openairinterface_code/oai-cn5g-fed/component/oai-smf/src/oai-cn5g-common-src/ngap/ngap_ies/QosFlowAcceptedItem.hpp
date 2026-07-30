/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _QOS_FLOW_ACCEPTED_ITEM_H_
#define _QOS_FLOW_ACCEPTED_ITEM_H_

#include "QosFlowIdentifier.hpp"

extern "C" {
#include "Ngap_QosFlowAcceptedItem.h"
}

namespace oai::ngap {

class QosFlowAcceptedItem {
 public:
  QosFlowAcceptedItem();
  virtual ~QosFlowAcceptedItem();

  void setQosFlowIdentifier(const QosFlowIdentifier& qosFlowIdentifier);
  void getQosFlowIdentifier(QosFlowIdentifier& qosFlowIdentifier) const;

  /*
  void setCurrentQoSParametersSetIndex(uint32_t&
          currentQoSParametersSetIndex);
  void getCurrentQoSParametersSetIndex(std::optional<uint32_t>&
                  currentQoSParametersSetIndex) const;
*/
  bool encode(Ngap_QosFlowAcceptedItem_t&) const;
  bool decode(const Ngap_QosFlowAcceptedItem_t&);

 private:
  QosFlowIdentifier m_QosFlowIdentifier;  // Mandatory
  // std::optional<uint32_t>
  //     m_CurrentQoSParametersSetIndex;  // Optional
};

}  // namespace oai::ngap

#endif
