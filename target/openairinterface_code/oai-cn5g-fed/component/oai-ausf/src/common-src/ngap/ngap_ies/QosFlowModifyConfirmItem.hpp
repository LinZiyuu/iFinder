/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _QOS_FLOW_MODIFY_CONFIRM_ITEM_H_
#define _QOS_FLOW_MODIFY_CONFIRM_ITEM_H_

#include "QosFlowIdentifier.hpp"

extern "C" {
#include "Ngap_QosFlowModifyConfirmItem.h"
}

namespace oai::ngap {

class QosFlowModifyConfirmItem {
 public:
  QosFlowModifyConfirmItem();
  virtual ~QosFlowModifyConfirmItem();

  void setQosFlowIdentifier(const QosFlowIdentifier& qosFlowIdentifier);
  void getQosFlowIdentifier(QosFlowIdentifier& qosFlowIdentifier) const;

  bool encode(Ngap_QosFlowModifyConfirmItem_t&) const;
  bool decode(const Ngap_QosFlowModifyConfirmItem_t&);

 private:
  QosFlowIdentifier m_QosFlowIdentifier;  // Mandatory
};

}  // namespace oai::ngap

#endif
