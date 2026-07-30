/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _NON_DYNAMIC_5QI_DESCRIPTOR_H_
#define _NON_DYNAMIC_5QI_DESCRIPTOR_H_

#include <optional>

#include "AveragingWindow.hpp"
#include "FiveQI.hpp"
#include "MaximumDataBurstVolume.hpp"
#include "PriorityLevelQos.hpp"

extern "C" {
#include "Ngap_NonDynamic5QIDescriptor.h"
}

namespace oai::ngap {

class NonDynamic5qiDescriptor {
 public:
  NonDynamic5qiDescriptor();
  NonDynamic5qiDescriptor(
      const FiveQI& fiveQI,
      const std::optional<PriorityLevelQos>& priorityLevelQos,
      const std::optional<AveragingWindow>& averagingWindow,
      const std::optional<MaximumDataBurstVolume>& maximumDataBurstVolume);
  virtual ~NonDynamic5qiDescriptor();

  void set(
      const FiveQI& fiveQI,
      const std::optional<PriorityLevelQos>& priorityLevelQos,
      const std::optional<AveragingWindow>& averagingWindow,
      const std::optional<MaximumDataBurstVolume>& maximumDataBurstVolume);
  void get(
      FiveQI& fiveQI, std::optional<PriorityLevelQos>& priorityLevelQos,
      std::optional<AveragingWindow>& averagingWindow,
      std::optional<MaximumDataBurstVolume>& maximumDataBurstVolume) const;

  bool encode(Ngap_NonDynamic5QIDescriptor_t&) const;
  bool decode(const Ngap_NonDynamic5QIDescriptor_t&);

 private:
  FiveQI m_FiveQI;                                                 // Mandatory
  std::optional<PriorityLevelQos> m_PriorityLevelQos;              // Optional
  std::optional<AveragingWindow> m_AveragingWindow;                // Optional
  std::optional<MaximumDataBurstVolume> m_MaximumDataBurstVolume;  // Optional
};
}  // namespace oai::ngap

#endif
