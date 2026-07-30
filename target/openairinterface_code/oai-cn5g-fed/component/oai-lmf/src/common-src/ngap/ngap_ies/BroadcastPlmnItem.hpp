/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _BROADCAST_PLMN_ITEM_H
#define _BROADCAST_PLMN_ITEM_H

#include <vector>

#include "PlmnId.hpp"
#include "SNssai.hpp"

extern "C" {
#include "Ngap_BroadcastPLMNItem.h"
}

namespace oai::ngap {

class BroadcastPlmnItem {
 public:
  BroadcastPlmnItem();
  virtual ~BroadcastPlmnItem();

  void set(const PlmnId& plmn, const std::vector<SNssai>& sliceList);
  void get(PlmnId& plmn, std::vector<SNssai>& sliceList) const;

  bool encode(Ngap_BroadcastPLMNItem_t&) const;
  bool decode(const Ngap_BroadcastPLMNItem_t&);

 private:
  PlmnId m_Plmn;                             // Mandatory
  std::vector<SNssai> m_SupportedSliceList;  // Tai Slice Support List
                                             // (Mandatory)
};
}  // namespace oai::ngap
#endif
