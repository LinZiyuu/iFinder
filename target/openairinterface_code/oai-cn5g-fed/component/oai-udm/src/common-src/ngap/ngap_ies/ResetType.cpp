/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "ResetType.hpp"

#include "utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
ResetType::ResetType() {
  m_Present           = Ngap_ResetType_PR_NOTHING;
  m_NgInterface       = std::nullopt;
  m_PartOfNgInterface = std::nullopt;
}

//------------------------------------------------------------------------------
ResetType::~ResetType() {}

//------------------------------------------------------------------------------
void ResetType::setResetType(const long& ngInterface) {
  m_Present           = Ngap_ResetType_PR_nG_Interface;
  m_NgInterface       = std::make_optional<long>(ngInterface);
  m_PartOfNgInterface = std::nullopt;
}

//------------------------------------------------------------------------------
void ResetType::setResetType(
    const std::vector<UeAssociatedLogicalNgConnectionItem>& list) {
  m_Present     = Ngap_ResetType_PR_partOfNG_Interface;
  m_NgInterface = std::nullopt;

  UeAssociatedLogicalNgConnectionList list_tmp = {};
  list_tmp.set(list);
  m_PartOfNgInterface =
      std::make_optional<UeAssociatedLogicalNgConnectionList>(list_tmp);
}

//------------------------------------------------------------------------------
void ResetType::getResetType(
    struct Ngap_UE_associatedLogicalNG_connectionList*&) const {
  // TODO:
  return;
}

//------------------------------------------------------------------------------
bool ResetType::encode(Ngap_ResetType_t& type) const {
  // TODO:
  return true;
}

//------------------------------------------------------------------------------
bool ResetType::decode(const Ngap_ResetType_t& type) {
  m_Present = type.present;
  if (type.present == Ngap_ResetType_PR_nG_Interface) {
    m_NgInterface = std::make_optional<long>((long) type.choice.nG_Interface);
    return true;
  } else if (type.present == Ngap_ResetType_PR_partOfNG_Interface) {
    UeAssociatedLogicalNgConnectionList list_tmp = {};
    list_tmp.decode(*type.choice.partOfNG_Interface);
    m_PartOfNgInterface =
        std::make_optional<UeAssociatedLogicalNgConnectionList>(list_tmp);
  } else {
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
void ResetType::getResetType(long& resetType) const {
  // TODO
}

//------------------------------------------------------------------------------
uint8_t ResetType::getResetType() const {
  return m_Present;
}

//------------------------------------------------------------------------------
void ResetType::getUeAssociatedLogicalNgConnectionList(
    struct Ngap_UE_associatedLogicalNG_connectionList*& list) const {
  // TODO:
}

//------------------------------------------------------------------------------
void ResetType::setUeAssociatedLogicalNgConnectionList(
    const std::vector<UeAssociatedLogicalNgConnectionItem>& list) {
  m_Present     = Ngap_ResetType_PR_partOfNG_Interface;
  m_NgInterface = std::nullopt;
  UeAssociatedLogicalNgConnectionList list_tmp = {};
  list_tmp.set(list);
  m_PartOfNgInterface =
      std::make_optional<UeAssociatedLogicalNgConnectionList>(list_tmp);
}

//------------------------------------------------------------------------------
void ResetType::getUeAssociatedLogicalNgConnectionList(
    std::vector<UeAssociatedLogicalNgConnectionItem>& list) const {
  if (m_PartOfNgInterface.has_value()) {
    m_PartOfNgInterface.value().get(list);
  }
}

}  // namespace oai::ngap
