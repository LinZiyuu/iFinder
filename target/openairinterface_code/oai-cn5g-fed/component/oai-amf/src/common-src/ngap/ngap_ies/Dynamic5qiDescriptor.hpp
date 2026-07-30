/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _DYNAMIC_5QI_DESCRIPTOR_H_
#define _DYNAMIC_5QI_DESCRIPTOR_H_

#include <optional>

#include "AveragingWindow.hpp"
#include "DelayCritical.hpp"
#include "FiveQI.hpp"
#include "MaximumDataBurstVolume.hpp"
#include "PacketDelayBudget.hpp"
#include "PacketErrorRate.hpp"
#include "PriorityLevelQos.hpp"

extern "C" {
#include "Ngap_Dynamic5QIDescriptor.h"
}

namespace oai::ngap {

class Dynamic5qiDescriptor {
 public:
  Dynamic5qiDescriptor();
  virtual ~Dynamic5qiDescriptor();

  void set(
      const PriorityLevelQos& priorityLevelQos,
      const PacketDelayBudget& packetDelayBudget,
      const PacketErrorRate& packetErrorRate,
      const std::optional<FiveQI>& fiveQI,
      const std::optional<DelayCritical>& delayCritical,
      const std::optional<AveragingWindow>& averagingWindow,
      const std::optional<MaximumDataBurstVolume>& maximumDataBurstVolume);

  bool get(
      PriorityLevelQos& priorityLevelQos, PacketDelayBudget& packetDelayBudget,
      PacketErrorRate& packetErrorRate, std::optional<FiveQI>& fiveQI,
      std::optional<DelayCritical>& delayCritical,
      std::optional<AveragingWindow>& averagingWindow,
      std::optional<MaximumDataBurstVolume>& maximumDataBurstVolume) const;

  bool encode(Ngap_Dynamic5QIDescriptor_t&) const;
  bool decode(const Ngap_Dynamic5QIDescriptor_t&);

 private:
  PriorityLevelQos m_PriorityLevelQos;    // Mandatory
  PacketDelayBudget m_PacketDelayBudget;  // Mandatory
  PacketErrorRate m_PacketErrorRate;      // Mandatory

  std::optional<FiveQI> m_FiveQI;                    // Optional
  std::optional<DelayCritical> m_DelayCritical;      // Conditional
  std::optional<AveragingWindow> m_AveragingWindow;  // Conditional
  std::optional<MaximumDataBurstVolume> m_MaximumDataBurstVolume;  // Optional
};
}  // namespace oai::ngap

#endif
