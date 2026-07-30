/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _UNAVAILABLE_GUAMI_ITEM_H
#define _UNAVAILABLE_GUAMI_ITEM_H

#include <optional>

#include "AmfName.hpp"
#include "Guami.hpp"
#include "TimerApproachForGuamiRemoval.hpp"

extern "C" {
#include "Ngap_UnavailableGUAMIItem.h"
}

namespace oai::ngap {

class UnavailableGuamiItem {
 public:
  UnavailableGuamiItem();
  virtual ~UnavailableGuamiItem();

  void setGuami(const Guami& guami);
  void getGuami(Guami& guami) const;

  void setTimerApproachForGuamiRemoval(
      const TimerApproachForGuamiRemoval& timer);
  void getTimerApproachForGuamiRemoval(
      std::optional<TimerApproachForGuamiRemoval>& timer) const;

  void setBackupAmfName(const AmfName& name);
  void getBackupAmfName(std::optional<AmfName>& name) const;

  bool encode(Ngap_UnavailableGUAMIItem& item) const;
  bool decode(const Ngap_UnavailableGUAMIItem& item);

 private:
  Guami m_Guami;
  std::optional<TimerApproachForGuamiRemoval>
      m_TimerApproachForGuamiRemoval;      // Optional
  std::optional<AmfName> m_BackupAmfName;  // Optional
};

}  // namespace oai::ngap

#endif
