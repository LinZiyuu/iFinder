/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _QOS_FLOW_MODIFY_CONFIRM_LIST_H_
#define _QOS_FLOW_MODIFY_CONFIRM_LIST_H_
#include <vector>

#include "QosFlowModifyConfirmItem.hpp"

extern "C" {
#include "Ngap_QosFlowModifyConfirmList.h"
}

namespace oai::ngap {

class QosFlowModifyConfirmList {
 public:
  QosFlowModifyConfirmList();
  virtual ~QosFlowModifyConfirmList();

  void set(const std::vector<QosFlowModifyConfirmItem>& list);
  void get(std::vector<QosFlowModifyConfirmItem>& list) const;

  void addItem(const QosFlowModifyConfirmItem& item);

  bool encode(Ngap_QosFlowModifyConfirmList_t& list) const;
  bool decode(const Ngap_QosFlowModifyConfirmList_t& list);

 private:
  std::vector<QosFlowModifyConfirmItem> m_ItemList;
  constexpr static uint8_t KMaxNoOfQosFlows = 64;
};

}  // namespace oai::ngap

#endif
