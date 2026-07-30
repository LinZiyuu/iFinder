/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _QOS_FLOW_TO_BE_FORWARDED_LIST_H_
#define _QOS_FLOW_TO_BE_FORWARDED_LIST_H_

#include <vector>

#include "QosFlowToBeForwardedItem.hpp"

extern "C" {
#include "Ngap_QosFlowToBeForwardedList.h"
}

namespace oai::ngap {
class QosFlowToBeForwardedList {
 public:
  QosFlowToBeForwardedList();
  virtual ~QosFlowToBeForwardedList(){};

  void set(const std::vector<QosFlowToBeForwardedItem>& list);
  void get(std::vector<QosFlowToBeForwardedItem>& list) const;

  bool encode(Ngap_QosFlowToBeForwardedList*& list) const;
  bool decode(const Ngap_QosFlowToBeForwardedList& list);

 private:
  std::vector<QosFlowToBeForwardedItem> m_ItemList;
  constexpr static uint8_t kMaxNoOfQosFlows = 64;
};
}  // namespace oai::ngap
#endif
