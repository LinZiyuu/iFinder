/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _ASSOCIATED_QOS_FLOW_LIST_H_
#define _ASSOCIATED_QOS_FLOW_LIST_H_

#include <vector>

#include "AssociatedQosFlowItem.hpp"

extern "C" {
#include "Ngap_AssociatedQosFlowList.h"
}

namespace oai::ngap {

class AssociatedQosFlowList {
 public:
  AssociatedQosFlowList();
  virtual ~AssociatedQosFlowList();

  void set(const std::vector<AssociatedQosFlowItem>& item_list);
  void get(std::vector<AssociatedQosFlowItem>& item_list) const;

  bool encode(Ngap_AssociatedQosFlowList_t& associatedQosFlowList) const;
  bool decode(const Ngap_AssociatedQosFlowList_t& associatedQosFlowList);

 private:
  std::vector<AssociatedQosFlowItem> m_List;
  constexpr static uint8_t kMaxNoOfQoSFlows = 64;
};

}  // namespace oai::ngap

#endif
