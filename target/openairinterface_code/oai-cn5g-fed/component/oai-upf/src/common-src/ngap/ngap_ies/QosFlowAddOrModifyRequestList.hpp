/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _QOS_FLOW_ADD_OR_MODIFY_REQUEST_LIST_H_
#define _QOS_FLOW_ADD_OR_MODIFY_REQUEST_LIST_H_
#include <vector>

#include "QosFlowAddOrModifyRequestItem.hpp"

extern "C" {
#include "Ngap_QosFlowAddOrModifyRequestList.h"
}

namespace oai::ngap {

class QosFlowAddOrModifyRequestList {
 public:
  QosFlowAddOrModifyRequestList();
  virtual ~QosFlowAddOrModifyRequestList();

  void set(const std::vector<QosFlowAddOrModifyRequestItem>& list);
  void get(std::vector<QosFlowAddOrModifyRequestItem>& list) const;

  void addItem(const QosFlowAddOrModifyRequestItem& item);

  bool encode(Ngap_QosFlowAddOrModifyRequestList_t& list) const;
  bool decode(const Ngap_QosFlowAddOrModifyRequestList_t& list);

 private:
  std::vector<QosFlowAddOrModifyRequestItem> m_ItemList;
  constexpr static uint8_t KMaxNoOfQosFlows = 64;
};

}  // namespace oai::ngap

#endif
