/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _SUPPORTED_TA_ITEM_H
#define _SUPPORTED_TA_ITEM_H

#include <vector>

#include "BroadcastPlmnItem.hpp"
#include "Tac.hpp"

extern "C" {
#include "Ngap_SupportedTAItem.h"
}

namespace oai::ngap {

class SupportedTaItem {
 public:
  SupportedTaItem();
  virtual ~SupportedTaItem();

  void setTac(const TAC& m_tac);
  void getTac(TAC& m_tac) const;
  TAC getTac() const;

  void setBroadcastPlmnList(const std::vector<BroadcastPlmnItem>& list);
  void getBroadcastPlmnList(std::vector<BroadcastPlmnItem>& list) const;
  std::vector<BroadcastPlmnItem> getBroadcastPlmnList() const;

  bool encode(Ngap_SupportedTAItem_t& ta) const;
  bool decode(const Ngap_SupportedTAItem_t& ta);

 private:
  TAC m_Tac;                                           // Mandatory
  std::vector<BroadcastPlmnItem> m_BroadcastPlmnList;  // Mandatory
};

}  // namespace oai::ngap

#endif
