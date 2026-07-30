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

class QosFlowItemWithDataForwarding {
 public:
  QosFlowItemWithDataForwarding();
  virtual ~QosFlowItemWithDataForwarding();

  void set(
      const QosFlowIdentifier& qfi,
      const std::optional<long>& dataForwardingAccepted);

  void setQosFlowIdentifier(const QosFlowIdentifier& qosFlowIdentifier);
  void getQosFlowIdentifier(QosFlowIdentifier& qosFlowIdentifier) const;

  void setDataForwardingAccepted(long dataForwardingAccepted);
  void getDataForwardingAccepted(
      std::optional<long>& dataForwardingAccepted) const;

  bool encode(Ngap_QosFlowItemWithDataForwarding_t&) const;
  bool decode(const Ngap_QosFlowItemWithDataForwarding_t&);

 private:
  QosFlowIdentifier m_QosFlowIdentifier;         // Mandatory
  std::optional<long> m_DataForwardingAccepted;  // Optional
  // TODO: Current QoS Parameters Set Index
};
}  // namespace oai::ngap

#endif  // !_QOSFLOWITEMWITHDATAFORWARDING_H_
