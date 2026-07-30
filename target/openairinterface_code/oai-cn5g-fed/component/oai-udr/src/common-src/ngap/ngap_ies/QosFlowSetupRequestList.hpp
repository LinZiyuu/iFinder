/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _QOS_FLOW_SETUP_REQUEST_LIST_H_
#define _QOS_FLOW_SETUP_REQUEST_LIST_H_

#include <vector>

#include "QosFlowSetupRequestItem.hpp"

extern "C" {
#include "Ngap_QosFlowSetupRequestList.h"
}

namespace oai::ngap {

class QosFlowSetupRequestList {
 public:
  QosFlowSetupRequestList();
  virtual ~QosFlowSetupRequestList();

  void set(const std::vector<QosFlowSetupRequestItem>& list);
  void get(std::vector<QosFlowSetupRequestItem>& list) const;

  bool encode(Ngap_QosFlowSetupRequestList_t& qosFlowSetupRequestList) const;
  bool decode(const Ngap_QosFlowSetupRequestList_t& qosFlowSetupRequestList);

 private:
  std::vector<QosFlowSetupRequestItem> m_ItemList;
  constexpr static uint8_t kMaxNoOfQoSFlows = 64;
};
}  // namespace oai::ngap
#endif
