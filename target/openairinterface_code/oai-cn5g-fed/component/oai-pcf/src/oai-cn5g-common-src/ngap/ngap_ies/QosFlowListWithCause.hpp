/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _QOS_FLOW_LIST_WITH_CAUSE_H_
#define _QOS_FLOW_LIST_WITH_CAUSE_H_

#include <vector>

#include "QosFlowWithCauseItem.hpp"

extern "C" {
#include "Ngap_QosFlowListWithCause.h"
}

namespace oai::ngap {

class QosFlowListWithCause {
 public:
  QosFlowListWithCause();
  virtual ~QosFlowListWithCause();

  void set(const std::vector<QosFlowWithCauseItem>& list);
  void get(std::vector<QosFlowWithCauseItem>& list) const;

  void addItem(const QosFlowWithCauseItem& item);

  bool encode(Ngap_QosFlowListWithCause_t& list) const;
  bool decode(const Ngap_QosFlowListWithCause_t& list);

 private:
  std::vector<QosFlowWithCauseItem> m_ItemList;
  constexpr static uint8_t KMaxNoOfQosFlows = 64;
};

}  // namespace oai::ngap

#endif
