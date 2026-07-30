/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceModifyListModRes.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceModifyListModRes::PduSessionResourceModifyListModRes() {}

//------------------------------------------------------------------------------
PduSessionResourceModifyListModRes::~PduSessionResourceModifyListModRes() {}

//------------------------------------------------------------------------------
void PduSessionResourceModifyListModRes::set(
    const std::vector<PduSessionResourceModifyItemModRes>& list) {
  m_ItemList = list;
}

//------------------------------------------------------------------------------
bool PduSessionResourceModifyListModRes::encode(
    Ngap_PDUSessionResourceModifyListModRes_t& list) const {
  for (auto pdu : m_ItemList) {
    Ngap_PDUSessionResourceModifyItemModRes_t* item =
        (Ngap_PDUSessionResourceModifyItemModRes_t*) calloc(
            1, sizeof(Ngap_PDUSessionResourceModifyItemModRes_t));

    if (!item) return false;
    if (!pdu.encode(*item)) return false;
    if (ASN_SEQUENCE_ADD(&list.list, item) != 0) return false;
  }

  return true;
}

//------------------------------------------------------------------------------
bool PduSessionResourceModifyListModRes::decode(
    const Ngap_PDUSessionResourceModifyListModRes_t&
        pdu_session_resource_modify_list_mod_res) {
  uint32_t num_pdu_sessions =
      pdu_session_resource_modify_list_mod_res.list.count;

  for (int i = 0; i < num_pdu_sessions; i++) {
    PduSessionResourceModifyItemModRes item = {};

    if (!item.decode(*pdu_session_resource_modify_list_mod_res.list.array[i]))
      return false;
    m_ItemList.push_back(item);
  }

  return true;
}

//------------------------------------------------------------------------------
void PduSessionResourceModifyListModRes::get(
    std::vector<PduSessionResourceModifyItemModRes>& list) const {
  list = m_ItemList;
}

}  // namespace oai::ngap
