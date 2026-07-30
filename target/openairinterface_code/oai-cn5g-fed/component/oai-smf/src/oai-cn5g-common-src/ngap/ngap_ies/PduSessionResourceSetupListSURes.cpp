/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceSetupListSURes.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceSetupListSURes::PduSessionResourceSetupListSURes() {}

//------------------------------------------------------------------------------
PduSessionResourceSetupListSURes::~PduSessionResourceSetupListSURes() {}

//------------------------------------------------------------------------------
void PduSessionResourceSetupListSURes::set(
    const std::vector<PduSessionResourceSetupItemSURes>& list) {
  m_ItemList = list;
}

//------------------------------------------------------------------------------
void PduSessionResourceSetupListSURes::get(
    std::vector<PduSessionResourceSetupItemSURes>& list) const {
  list = m_ItemList;
}

//------------------------------------------------------------------------------
bool PduSessionResourceSetupListSURes::encode(
    Ngap_PDUSessionResourceSetupListSURes_t& pduSessionResourceList) const {
  for (auto& item : m_ItemList) {
    Ngap_PDUSessionResourceSetupItemSURes_t* response =
        (Ngap_PDUSessionResourceSetupItemSURes_t*) calloc(
            1, sizeof(Ngap_PDUSessionResourceSetupItemSURes_t));
    if (!response) return false;
    if (!item.encode(*response)) return false;
    if (ASN_SEQUENCE_ADD(&pduSessionResourceList.list, response) != 0)
      return false;
  }

  return true;
}

//------------------------------------------------------------------------------
bool PduSessionResourceSetupListSURes::decode(
    const Ngap_PDUSessionResourceSetupListSURes_t& pduSessionResourceList) {
  for (int i = 0; i < pduSessionResourceList.list.count; i++) {
    PduSessionResourceSetupItemSURes item = {};
    if (!item.decode(*pduSessionResourceList.list.array[i])) return false;
    m_ItemList.push_back(item);
  }

  return true;
}

}  // namespace oai::ngap
