/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _QOS_FLOW_ITEM_WITH_DATA_FORWARDING_H_
#define _QOS_FLOW_ITEM_WITH_DATA_FORWARDING_H_

#include <optional>

#include "QosFlowIdentifier.hpp"
#include "QosFlowLevelQosParameters.hpp"

extern "C" {
#include "Ngap_QosFlowItemWithDataForwarding.h"
}

namespace oai::ngap {

class QosFlowItemWithDataForWarding {
 public:
  QosFlowItemWithDataForWarding();
  virtual ~QosFlowItemWithDataForWarding();

  void set(
      const QosFlowIdentifier& qfi,
      const std::optional<long>& dataForwardingAccepted);

  void getQosFlowIdentifier(Ngap_QosFlowIdentifier_t& qfi) const;

  bool decode(const Ngap_QosFlowItemWithDataForwarding_t& qosFlowItem);
  // TODO: encode

 private:
  QosFlowIdentifier m_Qfi;                       // Mandatory
  std::optional<long> m_DataForwardingAccepted;  // Optional
};
}  // namespace oai::ngap

#endif  // !_QOSFLOWITEMWITHDATAFORWARDING_H_
