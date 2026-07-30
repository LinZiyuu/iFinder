/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _QOS_FLOW_ACCEPTED_LIST_H_
#define _QOS_FLOW_ACCEPTED_LIST_H_
#include <vector>

#include "QosFlowAcceptedItem.hpp"

extern "C" {
#include "Ngap_QosFlowAcceptedList.h"
}

namespace oai::ngap {

class QosFlowAcceptedList {
 public:
  QosFlowAcceptedList();
  virtual ~QosFlowAcceptedList();

  void set(const std::vector<QosFlowAcceptedItem>& list);
  void get(std::vector<QosFlowAcceptedItem>& list) const;

  void addItem(const QosFlowAcceptedItem& item);

  bool encode(Ngap_QosFlowAcceptedList_t& list) const;
  bool decode(const Ngap_QosFlowAcceptedList_t& list);

 private:
  std::vector<QosFlowAcceptedItem> m_ItemList;
  constexpr static uint8_t KMaxNoOfQosFlows = 64;
};

}  // namespace oai::ngap

#endif
