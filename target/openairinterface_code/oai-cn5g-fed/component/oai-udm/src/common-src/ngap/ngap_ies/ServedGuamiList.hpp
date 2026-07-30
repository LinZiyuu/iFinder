/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _SERVED_GUAMI_LIST_H_
#define _SERVED_GUAMI_LIST_H_

#include <vector>

#include "ServedGuamiItem.hpp"

extern "C" {
#include "Ngap_ServedGUAMIList.h"
}

namespace oai::ngap {

class ServedGuamiList {
 public:
  ServedGuamiList();
  virtual ~ServedGuamiList();

  void set(const std::vector<ServedGuamiItem>& list);
  void get(std::vector<ServedGuamiItem>& list) const;

  void addItem(const ServedGuamiItem& item);

  bool encode(Ngap_ServedGUAMIList_t&) const;
  bool decode(const Ngap_ServedGUAMIList_t&);

 private:
  std::vector<ServedGuamiItem> m_ItemList;
};

}  // namespace oai::ngap

#endif
