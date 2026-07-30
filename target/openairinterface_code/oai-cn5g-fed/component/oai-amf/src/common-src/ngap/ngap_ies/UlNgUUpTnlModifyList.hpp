/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _UP_NGU_UP_TNL_MODIFY_LIST_H_
#define _UP_NGU_UP_TNL_MODIFY_LIST_H_

#include <vector>
#include "UlNgUUpTnlModifyItem.hpp"

extern "C" {
#include "Ngap_UL-NGU-UP-TNLModifyList.h"
}

namespace oai::ngap {

class UlNgUUpTnlModifyList {
 public:
  UlNgUUpTnlModifyList();
  virtual ~UlNgUUpTnlModifyList();

  void set(const std::vector<UlNgUUpTnlModifyItem>& list);
  void get(std::vector<UlNgUUpTnlModifyItem>& list) const;

  void addItem(const UlNgUUpTnlModifyItem& item);

  bool encode(Ngap_UL_NGU_UP_TNLModifyList_t& list) const;
  bool decode(const Ngap_UL_NGU_UP_TNLModifyList_t& list);

 private:
  std::vector<UlNgUUpTnlModifyItem> m_ItemList;
  constexpr static uint8_t KMaxNoOfMultiConnectivity = 4;
};

}  // namespace oai::ngap

#endif
