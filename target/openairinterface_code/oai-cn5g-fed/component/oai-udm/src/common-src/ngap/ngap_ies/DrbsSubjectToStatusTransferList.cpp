/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "DrbsSubjectToStatusTransferList.hpp"

#include "logger_base.hpp"
#include "utils.hpp"

namespace oai::ngap {
//------------------------------------------------------------------------------
DrbSubjectToStatusTransferList::DrbSubjectToStatusTransferList() {}

//------------------------------------------------------------------------------
DrbSubjectToStatusTransferList::~DrbSubjectToStatusTransferList() {}

//------------------------------------------------------------------------------
void DrbSubjectToStatusTransferList::set(
    const std::vector<DrbSubjectToStatusTransferItem>& list) {
  m_ItemList = list;
}

//------------------------------------------------------------------------------
void DrbSubjectToStatusTransferList::get(
    std::vector<DrbSubjectToStatusTransferItem>& list) const {
  list = m_ItemList;
}

//------------------------------------------------------------------------------
bool DrbSubjectToStatusTransferList::encode(
    Ngap_DRBsSubjectToStatusTransferList_t& drbsSubjectToStatusTransferList)
    const {
  for (auto& item : m_ItemList) {
    Ngap_DRBsSubjectToStatusTransferItem_t* ie =
        (Ngap_DRBsSubjectToStatusTransferItem_t*) calloc(
            1, sizeof(Ngap_DRBsSubjectToStatusTransferItem_t));
    if (!ie) return false;

    if (!item.encode(*ie)) {
      oai::logger::logger_common::ngap().error(
          "Encode DrbSubjectToStatusTransferList IE error!");
      oai::utils::utils::free_wrapper((void**) &ie);
      return false;
    }
    if (ASN_SEQUENCE_ADD(&drbsSubjectToStatusTransferList.list, ie) != 0) {
      oai::logger::logger_common::ngap().error(
          "ASN_SEQUENCE_ADD DrbSubjectToStatusTransferList IE error!");
      return false;
    }
  }
  return true;
}

//------------------------------------------------------------------------------
bool DrbSubjectToStatusTransferList::decode(
    const Ngap_DRBsSubjectToStatusTransferList_t&
        drbsSubjectToStatusTransferList) {
  for (int i = 0; i < drbsSubjectToStatusTransferList.list.count; i++) {
    DrbSubjectToStatusTransferItem item = {};
    if (!item.decode(*drbsSubjectToStatusTransferList.list.array[i])) {
      oai::logger::logger_common::ngap().error(
          "Decode DrbSubjectToStatusTransferList IE error!");
      return false;
    }
    m_ItemList.push_back(item);
  }
  return true;
}
}  // namespace oai::ngap
