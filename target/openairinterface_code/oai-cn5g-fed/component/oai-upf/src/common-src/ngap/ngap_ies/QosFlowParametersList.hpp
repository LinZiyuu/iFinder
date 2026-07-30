/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _QOS_FLOW_PARAMETERS_LIST_H_
#define _QOS_FLOW_PARAMETERS_LIST_H_
#include <vector>

#include "QosFlowParametersItem.hpp"

extern "C" {
#include "Ngap_QosFlowParametersList.h"
}

namespace oai::ngap {

class QosFlowParametersList {
 public:
  QosFlowParametersList();
  virtual ~QosFlowParametersList();

  void set(const std::vector<QosFlowParametersItem>& list);
  void get(std::vector<QosFlowParametersItem>& list) const;

  void addItem(const QosFlowParametersItem& item);

  bool encode(Ngap_QosFlowParametersList_t& list) const;
  bool decode(const Ngap_QosFlowParametersList_t& list);

 private:
  std::vector<QosFlowParametersItem> m_ItemList;
  constexpr static uint8_t KMaxNoOfQosFlows = 64;
};

}  // namespace oai::ngap

#endif
