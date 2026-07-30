/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _QOS_FLOW_LIST_WITH_DATA_FORWARDING_H_
#define _QOS_FLOW_LIST_WITH_DATA_FORWARDING_H_

#include <vector>

#include "QosFlowItemWithDataForwarding.hpp"
#include "QosFlowLevelQosParameters.hpp"

extern "C" {
#include "Ngap_QosFlowListWithDataForwarding.h"
}

namespace oai::ngap {
class QosFlowListWithDataForwarding {
 public:
  QosFlowListWithDataForwarding();
  virtual ~QosFlowListWithDataForwarding();

  void set(const std::vector<QosFlowItemWithDataForwarding>& list);
  void get(std::vector<QosFlowItemWithDataForwarding>& list) const;

  bool decode(const Ngap_QosFlowListWithDataForwarding_t& list);
  bool encode(Ngap_QosFlowListWithDataForwarding_t& list) const;

 private:
  std::vector<QosFlowItemWithDataForwarding> m_ItemList;
  constexpr static uint8_t KMaxNoOfQosFlows = 64;
};
}  // namespace oai::ngap
#endif
