/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _QOS_FLOW_NOTIFY_LIST_H_
#define _QOS_FLOW_NOTIFY_LIST_H_
#include <vector>

#include "QosFlowNotifyItem.hpp"

extern "C" {
#include "Ngap_QosFlowNotifyList.h"
}

namespace oai::ngap {

class QosFlowNotifyList {
 public:
  QosFlowNotifyList();
  virtual ~QosFlowNotifyList();

  void set(const std::vector<QosFlowNotifyItem>& list);
  void get(std::vector<QosFlowNotifyItem>& list) const;

  void addItem(const QosFlowNotifyItem& item);

  bool encode(Ngap_QosFlowNotifyList_t& list) const;
  bool decode(const Ngap_QosFlowNotifyList_t& list);

 private:
  std::vector<QosFlowNotifyItem> m_ItemList;
  constexpr static uint8_t KMaxNoOfQosFlows = 64;
};

}  // namespace oai::ngap

#endif
