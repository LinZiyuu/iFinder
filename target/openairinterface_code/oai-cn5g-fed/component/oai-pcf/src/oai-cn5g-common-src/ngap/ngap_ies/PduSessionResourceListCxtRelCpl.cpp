/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceListCxtRelCpl.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceListCxtRelCpl::PduSessionResourceListCxtRelCpl() {}

//------------------------------------------------------------------------------
PduSessionResourceListCxtRelCpl::~PduSessionResourceListCxtRelCpl() {}

//------------------------------------------------------------------------------
void PduSessionResourceListCxtRelCpl::set(
    const std::vector<PduSessionResourceItemCxtRelCpl>& list) {
  m_ItemList.clear();
  for (auto i : list) {
    m_ItemList.push_back(i);
  }
}

//------------------------------------------------------------------------------
void PduSessionResourceListCxtRelCpl::get(
    std::vector<PduSessionResourceItemCxtRelCpl>& list) const {
  list.clear();
  for (auto i : m_ItemList) {
    list.push_back(i);
  }
}

//------------------------------------------------------------------------------
bool PduSessionResourceListCxtRelCpl::encode(
    Ngap_PDUSessionResourceListCxtRelCpl_t& pduSessionResourceListCxtRelCpl)
    const {
  for (auto& cxtRelCpl : m_ItemList) {
    Ngap_PDUSessionResourceItemCxtRelCpl_t* item =
        (Ngap_PDUSessionResourceItemCxtRelCpl_t*) calloc(
            1, sizeof(Ngap_PDUSessionResourceItemCxtRelCpl_t));
    if (!item) return false;
    if (!cxtRelCpl.encode(*item)) return false;
    if (ASN_SEQUENCE_ADD(&pduSessionResourceListCxtRelCpl.list, item) != 0)
      return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool PduSessionResourceListCxtRelCpl::decode(
    const Ngap_PDUSessionResourceListCxtRelCpl_t&
        pduSessionResourceListCxtRelCpl) {
  for (int i = 0; i < pduSessionResourceListCxtRelCpl.list.count; i++) {
    PduSessionResourceItemCxtRelCpl item = {};
    if (!item.decode(*pduSessionResourceListCxtRelCpl.list.array[i]))
      return false;
    m_ItemList.push_back(item);
  }
  return true;
}

}  // namespace oai::ngap
