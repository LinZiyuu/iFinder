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

class GbrQosFlowInformation {
 public:
  GbrQosFlowInformation();
  GbrQosFlowInformation(
      const long& maximumFlowBitRateDl, const long& maximumFlowBitRateUl,
      const long& guaranteedFlowBitRateDl, const long& guaranteedFlowBitRateUl,
      const std::optional<NotificationControl>& notificationControl,
      const std::optional<PacketLossRate>& maximumPacketLossRateDl,
      const std::optional<PacketLossRate>& maximumPacketLossRateUl);
  virtual ~GbrQosFlowInformation();

  void set(
      const long& maximumFlowBitRateDl, const long& maximumFlowBitRateUl,
      const long& guaranteedFlowBitRateDl, const long& guaranteedFlowBitRateUl,
      const std::optional<NotificationControl>& notificationControl =
          std::nullopt,
      const std::optional<PacketLossRate>& maximumPacketLossRateDl =
          std::nullopt,
      const std::optional<PacketLossRate>& maximumPacketLossRateUl =
          std::nullopt);
  bool get(
      long& maximumFlowBitRateDl, long& maximumFlowBitRateUl,
      long& guaranteedFlowBitRateDl, long& guaranteedFlowBitRateUl,
      std::optional<NotificationControl>& notificationControl,
      std::optional<PacketLossRate>& maximumPacketLossRateDl,
      std::optional<PacketLossRate>& maximumPacketLossRateUl) const;

  bool encode(Ngap_GBR_QosInformation_t&) const;
  bool decode(const Ngap_GBR_QosInformation_t&);

 private:
  long m_MaximumFlowBitRateDl;                               // Mandatory
  long m_MaximumFlowBitRateUl;                               // Mandatory
  long m_GuaranteedFlowBitRateDl;                            // Mandatory
  long m_GuaranteedFlowBitRateUl;                            // Mandatory
  std::optional<NotificationControl> m_NotificationControl;  // Optional
  std::optional<PacketLossRate> m_MaximumPacketLossRateDl;   // Optional
  std::optional<PacketLossRate> m_MaximumPacketLossRateUl;   // Optional
};
}  // namespace oai::ngap

#endif
