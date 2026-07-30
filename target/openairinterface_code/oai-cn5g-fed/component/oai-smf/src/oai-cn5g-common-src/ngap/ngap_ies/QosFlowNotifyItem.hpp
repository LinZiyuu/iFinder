/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _QOS_FLOW_NOTIFY_ITEM_H_
#define _QOS_FLOW_NOTIFY_ITEM_H_

#include "NotificationCause.hpp"
#include "QosFlowIdentifier.hpp"

extern "C" {
#include "Ngap_QosFlowNotifyItem.h"
}

namespace oai::ngap {

class QosFlowNotifyItem {
 public:
  QosFlowNotifyItem();
  virtual ~QosFlowNotifyItem();

  void setQosFlowIdentifier(const QosFlowIdentifier& qosFlowIdentifier);
  void getQosFlowIdentifier(QosFlowIdentifier& qosFlowIdentifier) const;

  void setNotificationCause(const NotificationCause& notificationCause);
  void getNotificationCause(NotificationCause& notificationCause) const;

  /*
  void setCurrentQoSParametersSetIndex(uint32_t&
          currentQoSParametersSetIndex);
  void getCurrentQoSParametersSetIndex(std::optional<uint32_t>&
                  currentQoSParametersSetIndex) const;
*/
  bool encode(Ngap_QosFlowNotifyItem_t&) const;
  bool decode(const Ngap_QosFlowNotifyItem_t&);

 private:
  QosFlowIdentifier m_QosFlowIdentifier;  // Mandatory
  NotificationCause m_NotificationCause;
  // std::optional<uint32_t>
  //     m_CurrentQoSParametersSetIndex;  // Optional
};

}  // namespace oai::ngap

#endif
