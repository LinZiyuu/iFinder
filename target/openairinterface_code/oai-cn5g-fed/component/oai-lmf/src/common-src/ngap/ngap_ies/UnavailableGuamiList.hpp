/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _UNAVAILABLE_GUAMI_LIST_H_
#define _UNAVAILABLE_GUAMI_LIST_H_

#include <vector>

#include "UnavailableGuamiItem.hpp"

extern "C" {
#include "Ngap_UnavailableGUAMIList.h"
}

constexpr uint16_t kMaxNoOfServedGuami = 256;

namespace oai::ngap {

class UnavailableGuamiList {
 public:
  UnavailableGuamiList();
  virtual ~UnavailableGuamiList();

  void set(const std::vector<UnavailableGuamiItem>& list);
  void get(std::vector<UnavailableGuamiItem>& list) const;

  void addItem(const UnavailableGuamiItem& item);

  bool encode(Ngap_UnavailableGUAMIList_t&) const;
  bool decode(const Ngap_UnavailableGUAMIList_t&);

 private:
  std::vector<UnavailableGuamiItem> m_ItemList;
};

}  // namespace oai::ngap

#endif
