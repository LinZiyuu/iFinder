/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceSetupListCxtRes.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceSetupListCxtRes::PduSessionResourceSetupListCxtRes() {}

//------------------------------------------------------------------------------
PduSessionResourceSetupListCxtRes::~PduSessionResourceSetupListCxtRes() {}

//------------------------------------------------------------------------------
void PduSessionResourceSetupListCxtRes::set(
    const std::vector<PduSessionResourceSetupItemCxtRes>& list) {
  m_ItemList = list;
}

//------------------------------------------------------------------------------
void PduSessionResourceSetupListCxtRes::get(
    std::vector<PduSessionResourceSetupItemCxtRes>& list) const {
  list = m_ItemList;
}

//------------------------------------------------------------------------------
bool PduSessionResourceSetupListCxtRes::encode(
    Ngap_PDUSessionResourceSetupListCxtRes_t& pduSessionResourceSetupListCxtRes)
    const {
  for (std::vector<PduSessionResourceSetupItemCxtRes>::const_iterator it =
           m_ItemList.begin();
       it < m_ItemList.end(); ++it) {
    Ngap_PDUSessionResourceSetupItemCxtRes_t* response =
        (Ngap_PDUSessionResourceSetupItemCxtRes_t*) calloc(
            1, sizeof(Ngap_PDUSessionResourceSetupItemCxtRes_t));
    if (!response) return false;
    if (!it->encode(*response)) return false;
    if (ASN_SEQUENCE_ADD(&pduSessionResourceSetupListCxtRes.list, response) !=
        0)
      return false;
  }

  return true;
}

//------------------------------------------------------------------------------
bool PduSessionResourceSetupListCxtRes::decode(
    const Ngap_PDUSessionResourceSetupListCxtRes_t&
        pduSessionResourceSetupListCxtRes) {
  m_ItemList.reserve(pduSessionResourceSetupListCxtRes.list.count);
  for (int i = 0; i < pduSessionResourceSetupListCxtRes.list.count; i++) {
    PduSessionResourceSetupItemCxtRes item = {};
    if (!item.decode(*pduSessionResourceSetupListCxtRes.list.array[i]))
      return false;
    m_ItemList.push_back(item);
  }

  return true;
}

}  // namespace oai::ngap
