/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _QOS_FLOW_PER_TNL_INFORMATION_LIST_H_
#define _QOS_FLOW_PER_TNL_INFORMATION_LIST_H_

#include <vector>

#include "QosFlowPerTnlInformationItem.hpp"

extern "C" {
#include "Ngap_QosFlowPerTNLInformationList.h"
}

namespace oai::ngap {

class QosFlowPerTnlInformationList {
 public:
  QosFlowPerTnlInformationList();
  virtual ~QosFlowPerTnlInformationList();

  void set(const std::vector<QosFlowPerTnlInformationItem>& list);
  void get(std::vector<QosFlowPerTnlInformationItem>& list) const;

  bool encode(
      Ngap_QosFlowPerTNLInformationList_t& qosFlowPerTnlInformationList) const;
  bool decode(
      const Ngap_QosFlowPerTNLInformationList_t& qosFlowPerTnlInformationList);

 private:
  std::vector<QosFlowPerTnlInformationItem> m_ItemList;
  constexpr static uint8_t KMaxNoOfMultiConnectivityMinusOne = 3;
};
}  // namespace oai::ngap
#endif
