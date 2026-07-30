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

constexpr uint8_t kMaxNoQoSFlows = 64;

namespace oai::ngap {
class QosFlowListWithDataForwarding {
 public:
  QosFlowListWithDataForwarding();
  virtual ~QosFlowListWithDataForwarding();

  void set(const std::vector<QosFlowItemWithDataForWarding>& list);
  void get(std::vector<QosFlowItemWithDataForWarding>& list) const;

  bool decode(
      const Ngap_QosFlowListWithDataForwarding_t& qosFlowSetupResponseList);

 private:
  std::vector<QosFlowItemWithDataForWarding> m_ItemList;
};
}  // namespace oai::ngap
#endif
