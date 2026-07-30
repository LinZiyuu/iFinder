/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceFailedToSetupListSURes.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceFailedToSetupListSURes::
    PduSessionResourceFailedToSetupListSURes() {}

//------------------------------------------------------------------------------
PduSessionResourceFailedToSetupListSURes::
    ~PduSessionResourceFailedToSetupListSURes() {}

//------------------------------------------------------------------------------
void PduSessionResourceFailedToSetupListSURes::set(
    const std::vector<PduSessionResourceFailedToSetupItemSURes>& list) {
  m_ItemList = list;
}

//------------------------------------------------------------------------------
void PduSessionResourceFailedToSetupListSURes::get(
    std::vector<PduSessionResourceFailedToSetupItemSURes>& list) const {
  list = m_ItemList;
}
//------------------------------------------------------------------------------
bool PduSessionResourceFailedToSetupListSURes::encode(
    Ngap_PDUSessionResourceFailedToSetupListSURes_t& pduSessionResourceRes)
    const {
  for (auto& item : m_ItemList) {
    Ngap_PDUSessionResourceFailedToSetupItemSURes_t* item_su_res =
        (Ngap_PDUSessionResourceFailedToSetupItemSURes_t*) calloc(
            1, sizeof(Ngap_PDUSessionResourceFailedToSetupItemSURes_t));
    if (!item_su_res) return false;
    if (!item.encode(*item_su_res)) return false;
    if (ASN_SEQUENCE_ADD(&pduSessionResourceRes.list, item_su_res) != 0)
      return false;
  }

  return true;
}

//------------------------------------------------------------------------------
bool PduSessionResourceFailedToSetupListSURes::decode(
    const Ngap_PDUSessionResourceFailedToSetupListSURes_t&
        pduSessionResourceRes) {
  for (int i = 0; i < pduSessionResourceRes.list.count; i++) {
    PduSessionResourceFailedToSetupItemSURes item = {};
    if (!item.decode(*pduSessionResourceRes.list.array[i])) return false;
    m_ItemList.push_back(item);
  }

  return true;
}

}  // namespace oai::ngap
