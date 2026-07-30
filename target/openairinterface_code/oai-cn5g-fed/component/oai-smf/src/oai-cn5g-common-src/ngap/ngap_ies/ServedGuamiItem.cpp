/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "ServedGuamiItem.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
ServedGuamiItem::ServedGuamiItem() {
  m_BackupAmfName = std::nullopt;
}

//------------------------------------------------------------------------------
ServedGuamiItem::~ServedGuamiItem() {}

//------------------------------------------------------------------------------
void ServedGuamiItem::setGuami(const Guami& guami) {
  m_GuamiGroup = guami;
}

//------------------------------------------------------------------------------
void ServedGuamiItem::setBackupAmfName(const AmfName& amfName) {
  m_BackupAmfName = std::optional<AmfName>(amfName);
}

//------------------------------------------------------------------------------
bool ServedGuamiItem::getBackupAmfName(AmfName& amfName) const {
  if (!m_BackupAmfName.has_value()) return false;
  amfName = m_BackupAmfName.value();
  return true;
}
//------------------------------------------------------------------------------
bool ServedGuamiItem::encode(Ngap_ServedGUAMIItem& servedGUAMIItem) const {
  if (!m_GuamiGroup.encode(servedGUAMIItem.gUAMI)) return false;
  if (m_BackupAmfName.has_value()) {
    servedGUAMIItem.backupAMFName =
        (Ngap_AMFName_t*) calloc(1, sizeof(Ngap_AMFName_t));
    if (!servedGUAMIItem.backupAMFName) return false;
    if (!m_BackupAmfName.value().encode(*servedGUAMIItem.backupAMFName))
      return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool ServedGuamiItem::decode(const Ngap_ServedGUAMIItem& pdu) {
  if (!m_GuamiGroup.decode(pdu.gUAMI)) return false;
  if (pdu.backupAMFName) {
    AmfName amfName = {};
    if (!amfName.decode(*pdu.backupAMFName)) return false;
    m_BackupAmfName = std::optional<AmfName>(amfName);
  }
  return true;
}

//------------------------------------------------------------------------------
void ServedGuamiItem::getGuami(Guami& guami) const {
  guami = m_GuamiGroup;
}

}  // namespace oai::ngap
