/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _QOS_FLOW_FEEDBACK_LIST_H_
#define _QOS_FLOW_FEEDBACK_LIST_H_
#include <vector>

#include "QosFlowFeedbackItem.hpp"

extern "C" {
#include "Ngap_QosFlowFeedbackList.h"
}

namespace oai::ngap {

class QosFlowFeedbackList {
 public:
  QosFlowFeedbackList();
  virtual ~QosFlowFeedbackList();

  void set(const std::vector<QosFlowFeedbackItem>& list);
  void get(std::vector<QosFlowFeedbackItem>& list) const;

  void addItem(const QosFlowFeedbackItem& item);

  bool encode(Ngap_QosFlowFeedbackList_t& list) const;
  bool decode(const Ngap_QosFlowFeedbackList_t& list);

 private:
  std::vector<QosFlowFeedbackItem> m_ItemList;
  constexpr static uint8_t KMaxNoOfQosFlows = 64;
};

}  // namespace oai::ngap

#endif
