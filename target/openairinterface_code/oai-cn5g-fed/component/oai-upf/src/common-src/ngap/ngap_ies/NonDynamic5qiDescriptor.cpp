/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "NonDynamic5qiDescriptor.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
NonDynamic5qiDescriptor::NonDynamic5qiDescriptor() {
  m_PriorityLevelQos       = std::nullopt;
  m_AveragingWindow        = std::nullopt;
  m_MaximumDataBurstVolume = std::nullopt;
}

//------------------------------------------------------------------------------
NonDynamic5qiDescriptor::NonDynamic5qiDescriptor(
    const FiveQI& fiveQI,
    const std::optional<PriorityLevelQos>& priorityLevelQos,
    const std::optional<AveragingWindow>& averagingWindow,
    const std::optional<MaximumDataBurstVolume>& maximumDataBurstVolume) {
  m_FiveQI                 = fiveQI;
  m_PriorityLevelQos       = priorityLevelQos;
  m_AveragingWindow        = averagingWindow;
  m_MaximumDataBurstVolume = maximumDataBurstVolume;
}

//------------------------------------------------------------------------------
NonDynamic5qiDescriptor::~NonDynamic5qiDescriptor() {}

//------------------------------------------------------------------------------
void NonDynamic5qiDescriptor::set(
    const FiveQI& fiveQI,
    const std::optional<PriorityLevelQos>& priorityLevelQos,
    const std::optional<AveragingWindow>& averagingWindow,
    const std::optional<MaximumDataBurstVolume>& maximumDataBurstVolume) {
  m_FiveQI                 = fiveQI;
  m_PriorityLevelQos       = priorityLevelQos;
  m_AveragingWindow        = averagingWindow;
  m_MaximumDataBurstVolume = maximumDataBurstVolume;
}

//------------------------------------------------------------------------------
void NonDynamic5qiDescriptor::get(
    FiveQI& fiveQI, std::optional<PriorityLevelQos>& priorityLevelQos,
    std::optional<AveragingWindow>& averagingWindow,
    std::optional<MaximumDataBurstVolume>& maximumDataBurstVolume) const {
  fiveQI                 = m_FiveQI;
  priorityLevelQos       = m_PriorityLevelQos;
  averagingWindow        = m_AveragingWindow;
  maximumDataBurstVolume = m_MaximumDataBurstVolume;
}

//------------------------------------------------------------------------------
bool NonDynamic5qiDescriptor::encode(
    Ngap_NonDynamic5QIDescriptor_t& nonDynamic5qiDescriptor) const {
  if (!m_FiveQI.encode(nonDynamic5qiDescriptor.fiveQI)) return false;
  if (m_PriorityLevelQos.has_value()) {
    Ngap_PriorityLevelQos_t* plq =
        (Ngap_PriorityLevelQos_t*) calloc(1, sizeof(Ngap_PriorityLevelQos_t));
    if (!plq) return false;
    if (!m_PriorityLevelQos.value().encode(*plq)) return false;
    nonDynamic5qiDescriptor.priorityLevelQos = plq;
  }
  if (m_AveragingWindow.has_value()) {
    Ngap_AveragingWindow_t* aw =
        (Ngap_AveragingWindow_t*) calloc(1, sizeof(Ngap_AveragingWindow_t));
    if (!aw) return false;
    if (!m_AveragingWindow.value().encode(*aw)) return false;
    nonDynamic5qiDescriptor.averagingWindow = aw;
  }
  if (m_MaximumDataBurstVolume.has_value()) {
    Ngap_MaximumDataBurstVolume_t* mdbv =
        (Ngap_MaximumDataBurstVolume_t*) calloc(
            1, sizeof(Ngap_MaximumDataBurstVolume_t));
    if (!mdbv) return false;
    if (!m_MaximumDataBurstVolume.value().encode(*mdbv)) return false;
    nonDynamic5qiDescriptor.maximumDataBurstVolume = mdbv;
  }

  return true;
}

//------------------------------------------------------------------------------
bool NonDynamic5qiDescriptor::decode(
    const Ngap_NonDynamic5QIDescriptor_t& nonDynamic5qiDescriptor) {
  if (!m_FiveQI.decode(nonDynamic5qiDescriptor.fiveQI)) return false;
  if (nonDynamic5qiDescriptor.priorityLevelQos) {
    PriorityLevelQos tmp = {};
    if (!tmp.decode(*nonDynamic5qiDescriptor.priorityLevelQos)) return false;
    m_PriorityLevelQos = std::make_optional<PriorityLevelQos>(tmp);
  }
  if (nonDynamic5qiDescriptor.averagingWindow) {
    AveragingWindow tmp = {};
    if (!tmp.decode(*nonDynamic5qiDescriptor.averagingWindow)) return false;
    m_AveragingWindow = std::make_optional<AveragingWindow>(tmp);
  }
  if (nonDynamic5qiDescriptor.maximumDataBurstVolume) {
    MaximumDataBurstVolume tmp = {};
    if (!tmp.decode(*nonDynamic5qiDescriptor.maximumDataBurstVolume))
      return false;
    m_MaximumDataBurstVolume = std::make_optional<MaximumDataBurstVolume>(tmp);
  }

  return true;
}
}  // namespace oai::ngap
