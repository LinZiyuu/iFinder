/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "UnavailableGuamiItem.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
UnavailableGuamiItem::UnavailableGuamiItem() {
  m_TimerApproachForGuamiRemoval = std::nullopt;
  m_BackupAmfName                = std::nullopt;
}

//------------------------------------------------------------------------------
UnavailableGuamiItem::~UnavailableGuamiItem() {}

//------------------------------------------------------------------------------
void UnavailableGuamiItem::setGuami(const Guami& guami) {
  m_Guami = guami;
}

//------------------------------------------------------------------------------
void UnavailableGuamiItem::getGuami(Guami& guami) const {
  guami = m_Guami;
}

//------------------------------------------------------------------------------
void UnavailableGuamiItem::setTimerApproachForGuamiRemoval(
    const TimerApproachForGuamiRemoval& timer) {
  m_TimerApproachForGuamiRemoval =
      std::make_optional<TimerApproachForGuamiRemoval>(timer);
}

//------------------------------------------------------------------------------
void UnavailableGuamiItem::getTimerApproachForGuamiRemoval(
    std::optional<TimerApproachForGuamiRemoval>& timer) const {
  timer = m_TimerApproachForGuamiRemoval;
}

//------------------------------------------------------------------------------
void UnavailableGuamiItem::setBackupAmfName(const AmfName& name) {
  m_BackupAmfName = std::make_optional<AmfName>(name);
}

//------------------------------------------------------------------------------
void UnavailableGuamiItem::getBackupAmfName(
    std::optional<AmfName>& name) const {
  name = m_BackupAmfName;
}

//------------------------------------------------------------------------------
bool UnavailableGuamiItem::encode(Ngap_UnavailableGUAMIItem& item) const {
  if (!m_Guami.encode(item.gUAMI)) return false;
  if (m_TimerApproachForGuamiRemoval.has_value()) {
    if (!m_TimerApproachForGuamiRemoval.value().encode(
            *item.timerApproachForGUAMIRemoval))
      return false;
  }
  if (m_BackupAmfName.has_value())
    if (!m_BackupAmfName.value().encode(*item.backupAMFName)) return false;
  return true;
}

//------------------------------------------------------------------------------
bool UnavailableGuamiItem::decode(const Ngap_UnavailableGUAMIItem& item) {
  if (!m_Guami.decode(item.gUAMI)) return false;

  if (item.timerApproachForGUAMIRemoval) {
    TimerApproachForGuamiRemoval tmp = {};
    if (!tmp.decode(*item.timerApproachForGUAMIRemoval)) return false;
    m_TimerApproachForGuamiRemoval =
        std::make_optional<TimerApproachForGuamiRemoval>(tmp);
  }

  if (item.backupAMFName) {
    AmfName tmp = {};
    if (!tmp.decode(*item.backupAMFName)) return false;
    m_BackupAmfName = std::make_optional<AmfName>(tmp);
  }
  return true;
}

}  // namespace oai::ngap
