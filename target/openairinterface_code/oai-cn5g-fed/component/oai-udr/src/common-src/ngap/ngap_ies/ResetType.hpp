/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _RESET_TYPE_H_
#define _RESET_TYPE_H_

#include <optional>
#include <vector>

#include "UeAssociatedLogicalNgConnectionItem.hpp"
#include "UeAssociatedLogicalNgConnectionList.hpp"

extern "C" {
#include "Ngap_ResetType.h"
}

namespace oai::ngap {
class ResetType {
 public:
  ResetType();
  virtual ~ResetType();

  void setResetType(const long&);
  void setResetType(
      const std::vector<UeAssociatedLogicalNgConnectionItem>& list);
  void getResetType(struct Ngap_UE_associatedLogicalNG_connectionList*&) const;

  void getResetType(long&) const;
  uint8_t getResetType() const;

  void setUeAssociatedLogicalNgConnectionList(
      const std::vector<UeAssociatedLogicalNgConnectionItem>& list);

  void getUeAssociatedLogicalNgConnectionList(
      std::vector<UeAssociatedLogicalNgConnectionItem>& list) const;
  void getUeAssociatedLogicalNgConnectionList(
      struct Ngap_UE_associatedLogicalNG_connectionList*&) const;

  bool encode(Ngap_ResetType_t& type) const;
  bool decode(const Ngap_ResetType_t& type);

 private:
  Ngap_ResetType_PR m_Present;
  std::optional<long> m_NgInterface;
  std::optional<UeAssociatedLogicalNgConnectionList> m_PartOfNgInterface;
  //	struct Ngap_ProtocolIE_SingleContainer	*choice_Extensions;
};

}  // namespace oai::ngap

#endif
