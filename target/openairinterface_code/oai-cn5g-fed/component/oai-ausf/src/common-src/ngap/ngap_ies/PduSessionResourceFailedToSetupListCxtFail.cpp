/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceFailedToSetupListCxtFail.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceFailedToSetupListCxtFail::
    PduSessionResourceFailedToSetupListCxtFail() {}

//------------------------------------------------------------------------------
PduSessionResourceFailedToSetupListCxtFail::
    ~PduSessionResourceFailedToSetupListCxtFail() {}

//------------------------------------------------------------------------------
void PduSessionResourceFailedToSetupListCxtFail::set(
    const std::vector<PduSessionResourceFailedToSetupItemCxtFail>& list) {
  m_ItemList = list;
}

//------------------------------------------------------------------------------
void PduSessionResourceFailedToSetupListCxtFail::get(
    std::vector<PduSessionResourceFailedToSetupItemCxtFail>& list) const {
  list = m_ItemList;
}

//------------------------------------------------------------------------------
bool PduSessionResourceFailedToSetupListCxtFail::encode(
    Ngap_PDUSessionResourceFailedToSetupListCxtFail_t&
        pduSessionResourceFailedToSetupListCxtFail) const {
  for (std::vector<PduSessionResourceFailedToSetupItemCxtFail>::const_iterator
           it = m_ItemList.begin();
       it < m_ItemList.end(); ++it) {
    Ngap_PDUSessionResourceFailedToSetupItemCxtFail_t* failedToFailure =
        (Ngap_PDUSessionResourceFailedToSetupItemCxtFail_t*) calloc(
            1, sizeof(Ngap_PDUSessionResourceFailedToSetupItemCxtFail_t));
    if (!failedToFailure) return false;
    if (!it->encode(*failedToFailure)) return false;
    if (ASN_SEQUENCE_ADD(
            &pduSessionResourceFailedToSetupListCxtFail.list,
            failedToFailure) != 0)
      return false;
  }

  return true;
}

//------------------------------------------------------------------------------
bool PduSessionResourceFailedToSetupListCxtFail::decode(
    const Ngap_PDUSessionResourceFailedToSetupListCxtFail_t&
        pduSessionResourceFailedToSetupListCxtFail) {
  m_ItemList.reserve(pduSessionResourceFailedToSetupListCxtFail.list.count);

  for (int i = 0; i < pduSessionResourceFailedToSetupListCxtFail.list.count;
       i++) {
    PduSessionResourceFailedToSetupItemCxtFail itemCxtFail = {};
    if (!itemCxtFail.decode(
            *pduSessionResourceFailedToSetupListCxtFail.list.array[i]))
      return false;
    m_ItemList.push_back(itemCxtFail);
  }

  return true;
}

}  // namespace oai::ngap
