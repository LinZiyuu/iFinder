/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _QOS_FLOW_ITEM_WITH_CAUSE_H_
#define _QOS_FLOW_ITEM_WITH_CAUSE_H_

#include "QosFlowIdentifier.hpp"
#include "Cause.hpp"

extern "C" {
#include "Ngap_QosFlowWithCauseItem.h"
}

namespace oai::ngap {

class QosFlowWithCauseItem {
 public:
  QosFlowWithCauseItem();
  virtual ~QosFlowWithCauseItem();

  void set(const QosFlowIdentifier& qosFlowIdentifier, const Cause& cause);
  bool get(QosFlowIdentifier& qosFlowIdentifier, Cause& cause) const;

  void setQosFlowIdentifier(const QosFlowIdentifier& qosFlowIdentifier);
  bool getQosFlowIdentifier(QosFlowIdentifier& qosFlowIdentifier) const;

  void setCause(const Cause& cause);
  bool getCause(Cause& cause) const;

  bool encode(Ngap_QosFlowWithCauseItem_t&) const;
  bool decode(const Ngap_QosFlowWithCauseItem_t&);

 private:
  QosFlowIdentifier m_QosFlowIdentifier;  // Mandatory
  Cause m_Cause;                          // Mandatory
};

}  // namespace oai::ngap

#endif
