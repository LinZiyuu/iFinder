/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _QOS_FLOW_ADD_OR_MODIFY_RESPONSE_LIST_H_
#define _QOS_FLOW_ADD_OR_MODIFY_RESPONSE_LIST_H_
#include <vector>

#include "QosFlowAddOrModifyResponseItem.hpp"

extern "C" {
#include "Ngap_QosFlowAddOrModifyResponseList.h"
}

namespace oai::ngap {

class QosFlowAddOrModifyResponseList {
 public:
  QosFlowAddOrModifyResponseList();
  virtual ~QosFlowAddOrModifyResponseList();

  void set(const std::vector<QosFlowAddOrModifyResponseItem>& list);
  void get(std::vector<QosFlowAddOrModifyResponseItem>& list) const;

  void addItem(const QosFlowAddOrModifyResponseItem& item);

  bool encode(Ngap_QosFlowAddOrModifyResponseList_t& list) const;
  bool decode(const Ngap_QosFlowAddOrModifyResponseList_t& list);

 private:
  std::vector<QosFlowAddOrModifyResponseItem> m_ItemList;
  constexpr static uint8_t KMaxNoOfQosFlows = 64;
};

}  // namespace oai::ngap

#endif
