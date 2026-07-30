/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _SERVED_GUAMI_ITEM_H_
#define _SERVED_GUAMI_ITEM_H_

#include <optional>

#include "AmfName.hpp"
#include "Guami.hpp"

extern "C" {
#include "Ngap_ServedGUAMIItem.h"
}

namespace oai::ngap {

class ServedGuamiItem {
 public:
  ServedGuamiItem();
  virtual ~ServedGuamiItem();

  void setGuami(const Guami& guami);
  void getGuami(Guami& guami) const;

  void setBackupAmfName(const AmfName&);
  bool getBackupAmfName(AmfName&) const;

  bool encode(Ngap_ServedGUAMIItem&) const;
  bool decode(const Ngap_ServedGUAMIItem&);

 private:
  Guami m_GuamiGroup;                      // Mandatory
  std::optional<AmfName> m_BackupAmfName;  // Optional
  // bool backupAMFNameIsSet;
  // TODO: Guami Type (Optional)
};

}  // namespace oai::ngap

#endif
