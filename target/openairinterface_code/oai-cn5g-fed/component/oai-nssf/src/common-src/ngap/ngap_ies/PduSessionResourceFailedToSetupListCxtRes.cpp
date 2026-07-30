/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceFailedToSetupListCxtRes.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceFailedToSetupListCxtRes::
    PduSessionResourceFailedToSetupListCxtRes() {}

//------------------------------------------------------------------------------
PduSessionResourceFailedToSetupListCxtRes::
    ~PduSessionResourceFailedToSetupListCxtRes() {}

//------------------------------------------------------------------------------
void PduSessionResourceFailedToSetupListCxtRes::set(
    const std::vector<PduSessionResourceFailedToSetupItemCxtRes>& list) {
  m_ItemList = list;
}

//------------------------------------------------------------------------------
void PduSessionResourceFailedToSetupListCxtRes::get(
    std::vector<PduSessionResourceFailedToSetupItemCxtRes>& list) const {
  list = m_ItemList;
}

//------------------------------------------------------------------------------
bool PduSessionResourceFailedToSetupListCxtRes::encode(
    Ngap_PDUSessionResourceFailedToSetupListCxtRes_t&
        pduSessionResourceFailedToSetupListCxtRes) const {
  for (std::vector<PduSessionResourceFailedToSetupItemCxtRes>::const_iterator
           it = m_ItemList.begin();
       it < m_ItemList.end(); ++it) {
    Ngap_PDUSessionResourceFailedToSetupItemCxtRes_t* failedToResponse =
        (Ngap_PDUSessionResourceFailedToSetupItemCxtRes_t*) calloc(
            1, sizeof(Ngap_PDUSessionResourceFailedToSetupItemCxtRes_t));
    if (!failedToResponse) return false;

    if (!it->encode(*failedToResponse)) return false;
    if (ASN_SEQUENCE_ADD(
            &pduSessionResourceFailedToSetupListCxtRes.list,
            failedToResponse) != 0)
      return false;
  }

  return true;
}

//------------------------------------------------------------------------------
bool PduSessionResourceFailedToSetupListCxtRes::decode(
    const Ngap_PDUSessionResourceFailedToSetupListCxtRes_t&
        pduSessionResourceFailedToSetupListCxtRes) {
  m_ItemList.reserve(pduSessionResourceFailedToSetupListCxtRes.list.count);
  for (int i = 0; i < pduSessionResourceFailedToSetupListCxtRes.list.count;
       i++) {
    PduSessionResourceFailedToSetupItemCxtRes item = {};
    if (!item.decode(*pduSessionResourceFailedToSetupListCxtRes.list.array[i]))
      return false;
    m_ItemList.push_back(item);
  }

  return true;
}

}  // namespace oai::ngap
