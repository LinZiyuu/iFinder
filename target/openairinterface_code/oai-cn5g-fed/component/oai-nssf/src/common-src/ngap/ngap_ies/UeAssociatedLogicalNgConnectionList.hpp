/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _UE_ASSOCIATED_LOGICAL_NG_CONNECTION_LIST_H_
#define _UE_ASSOCIATED_LOGICAL_NG_CONNECTION_LIST_H_

#include <vector>

#include "UeAssociatedLogicalNgConnectionItem.hpp"

extern "C" {
#include "Ngap_ProtocolIE-Field.h"
#include "Ngap_UE-associatedLogicalNG-connectionList.h"
}

namespace oai::ngap {

class UeAssociatedLogicalNgConnectionList {
 public:
  UeAssociatedLogicalNgConnectionList();
  virtual ~UeAssociatedLogicalNgConnectionList();

  void set(const std::vector<UeAssociatedLogicalNgConnectionItem>& list);
  void get(std::vector<UeAssociatedLogicalNgConnectionItem>& list) const;

  void addItem(UeAssociatedLogicalNgConnectionItem& item);

  bool encode(Ngap_UE_associatedLogicalNG_connectionList_t& list) const;
  bool decode(const Ngap_UE_associatedLogicalNG_connectionList_t& list);

 private:
  std::vector<UeAssociatedLogicalNgConnectionItem> m_ItemList;
};

}  // namespace oai::ngap
#endif
