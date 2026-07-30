/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _QOS_FLOW_ADD_OR_MODIFY_RESPONSE_ITEM_H_
#define _QOS_FLOW_ADD_OR_MODIFY_RESPONSE_ITEM_H_

#include "QosFlowIdentifier.hpp"
#include "QosFlowLevelQosParameters.hpp"

extern "C" {
#include "Ngap_QosFlowAddOrModifyResponseItem.h"
}

namespace oai::ngap {

class QosFlowAddOrModifyResponseItem {
 public:
  QosFlowAddOrModifyResponseItem();
  virtual ~QosFlowAddOrModifyResponseItem();

  void setQosFlowIdentifier(const QosFlowIdentifier& qosFlowIdentifier);
  void getQosFlowIdentifier(QosFlowIdentifier& qosFlowIdentifier) const;

  /*
  void setCurrentQoSParametersSetIndex(uint32_t&
          currentQoSParametersSetIndex);
  void getCurrentQoSParametersSetIndex(std::optional<uint32_t>&
                  currentQoSParametersSetIndex) const;
*/
  bool encode(Ngap_QosFlowAddOrModifyResponseItem_t&) const;
  bool decode(const Ngap_QosFlowAddOrModifyResponseItem_t&);

 private:
  QosFlowIdentifier m_QosFlowIdentifier;  // Mandatory
                                          // std::optional<uint32_t>
  //     m_CurrentQoSParametersSetIndex;  // Optional
};

}  // namespace oai::ngap

#endif
