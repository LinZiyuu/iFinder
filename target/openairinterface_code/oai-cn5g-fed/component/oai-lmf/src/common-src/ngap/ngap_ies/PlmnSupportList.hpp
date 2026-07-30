/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PLMN_SUPPORT_LIST_H_
#define _PLMN_SUPPORT_LIST_H_

#include <vector>

#include "PlmnSupportItem.hpp"

extern "C" {
#include "Ngap_PLMNSupportList.h"
}

namespace oai::ngap {

class PlmnSupportList {
 public:
  PlmnSupportList();
  virtual ~PlmnSupportList();

  void set(const std::vector<PlmnSupportItem>& items);
  void get(std::vector<PlmnSupportItem>& items) const;

  void addItem(const PlmnSupportItem& item);

  bool encode(Ngap_PLMNSupportList_t&) const;
  bool decode(const Ngap_PLMNSupportList_t&);

 private:
  std::vector<PlmnSupportItem> m_List;
};

}  // namespace oai::ngap

#endif
