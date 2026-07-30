/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _UE_ASSOCIATED_LOGICAL_NG_CONNECTION_ITEM_H_
#define _UE_ASSOCIATED_LOGICAL_NG_CONNECTION_ITEM_H_

#include <optional>

#include "AmfUeNgapId.hpp"
#include "RanUeNgapId.hpp"

extern "C" {
#include "Ngap_ProtocolIE-Field.h"
#include "Ngap_UE-associatedLogicalNG-connectionItem.h"
}

namespace oai::ngap {

class UeAssociatedLogicalNgConnectionItem {
 public:
  UeAssociatedLogicalNgConnectionItem();
  virtual ~UeAssociatedLogicalNgConnectionItem(){};

  bool setAmfUeNgapId(const uint64_t& id);
  bool getAmfUeNgapId(uint64_t& id) const;
  void setRanUeNgapId(const uint32_t& id);
  bool getRanUeNgapId(uint32_t& id) const;

  void get(UeAssociatedLogicalNgConnectionItem& item) const;

  bool encode(Ngap_UE_associatedLogicalNG_connectionItem_t& item) const;
  bool decode(const Ngap_UE_associatedLogicalNG_connectionItem_t& item);

 private:
  std::optional<AmfUeNgapId> m_AmfUeNgapId;  // Optional
  std::optional<RanUeNgapId> m_RanUeNgapId;  // Optional
};

}  // namespace oai::ngap
#endif
