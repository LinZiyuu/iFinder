/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _GBR_QOS_INFORMATION_H_
#define _GBR_QOS_INFORMATION_H_

#include <optional>

#include "NotificationControl.hpp"
#include "PacketLossRate.hpp"

extern "C" {
#include "Ngap_GBR-QosInformation.h"
}

namespace oai::ngap {

class GbrQosInformation {
 public:
  GbrQosInformation();
  virtual ~GbrQosInformation();

  void set(
      const long& maximumFlowBitRateDl, const long& maximumFlowBitRateUl,
      const long& guaranteedFlowBitRateDl, const long& guaranteedFlowBitRateUl,
      const std::optional<NotificationControl>& notificationControl,
      const std::optional<PacketLossRate>& maximumPacketLossRateDl,
      const std::optional<PacketLossRate>& maximumPacketLossRateUl);
  bool get(
      long& maximumFlowBitRateDl, long& maximumFlowBitRateUl,
      long& guaranteedFlowBitRateDl, long& guaranteedFlowBitRateUl,
      std::optional<NotificationControl>& notificationControl,
      std::optional<PacketLossRate>& maximumPacketLossRateDl,
      std::optional<PacketLossRate>& maximumPacketLossRateUl);

  bool encode(Ngap_GBR_QosInformation_t&) const;
  bool decode(const Ngap_GBR_QosInformation_t&);

 private:
  long m_MaximumFlowBitRateDl;
  long m_MaximumFlowBitRateUl;
  long m_GuaranteedFlowBitRateDl;
  long m_GuaranteedFlowBitRateUl;
  std::optional<NotificationControl> m_NotificationControl;  // Optional
  std::optional<PacketLossRate> m_MaximumPacketLossRateDl;   // Optional
  std::optional<PacketLossRate> m_MaximumPacketLossRateUl;   // Optional
  // TODO: Alternative QoS Parameters Set List (Optional, Rel 16.14.0)
};
}  // namespace oai::ngap

#endif
