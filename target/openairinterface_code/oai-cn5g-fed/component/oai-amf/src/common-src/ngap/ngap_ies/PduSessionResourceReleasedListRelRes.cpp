/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceReleasedListRelRes.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceReleasedListRelRes::PduSessionResourceReleasedListRelRes() {}

//------------------------------------------------------------------------------
PduSessionResourceReleasedListRelRes::~PduSessionResourceReleasedListRelRes() {}

//------------------------------------------------------------------------------
void PduSessionResourceReleasedListRelRes::set(
    const std::vector<PduSessionResourceReleasedItemRelRes>& list) {
  m_ItemList = list;
}

//------------------------------------------------------------------------------
void PduSessionResourceReleasedListRelRes::get(
    std::vector<PduSessionResourceReleasedItemRelRes>& list) const {
  list = m_ItemList;
}

//------------------------------------------------------------------------------
bool PduSessionResourceReleasedListRelRes::encode(
    Ngap_PDUSessionResourceReleasedListRelRes_t& pduSessionResourceList) const {
  for (auto& item : m_ItemList) {
    Ngap_PDUSessionResourceReleasedItemRelRes_t* rel =
        (Ngap_PDUSessionResourceReleasedItemRelRes_t*) calloc(
            1, sizeof(Ngap_PDUSessionResourceReleasedItemRelRes_t));
    if (!rel) return false;
    if (!item.encode(*rel)) return false;
    if (ASN_SEQUENCE_ADD(&pduSessionResourceList.list, rel) != 0) return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool PduSessionResourceReleasedListRelRes::decode(
    const Ngap_PDUSessionResourceReleasedListRelRes_t& pduSessionResourceList) {
  for (int i = 0; i < pduSessionResourceList.list.count; i++) {
    PduSessionResourceReleasedItemRelRes item = {};
    if (!item.decode(*pduSessionResourceList.list.array[i])) return false;
    m_ItemList.push_back(item);
  }
  return true;
}

}  // namespace oai::ngap
