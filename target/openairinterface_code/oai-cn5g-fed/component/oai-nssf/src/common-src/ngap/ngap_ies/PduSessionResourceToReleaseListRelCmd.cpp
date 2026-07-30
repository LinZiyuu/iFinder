/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceToReleaseListRelCmd.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceToReleaseListRelCmd::PduSessionResourceToReleaseListRelCmd() {
}

//------------------------------------------------------------------------------
PduSessionResourceToReleaseListRelCmd::
    ~PduSessionResourceToReleaseListRelCmd() {}

//------------------------------------------------------------------------------
void PduSessionResourceToReleaseListRelCmd::set(
    const std::vector<PduSessionResourceToReleaseItemRelCmd>& list) {
  m_ItemList = list;
}

//------------------------------------------------------------------------------
void PduSessionResourceToReleaseListRelCmd::get(
    std::vector<PduSessionResourceToReleaseItemRelCmd>& list) const {
  list = m_ItemList;
}

//------------------------------------------------------------------------------
bool PduSessionResourceToReleaseListRelCmd::encode(
    Ngap_PDUSessionResourceToReleaseListRelCmd_t& pduSessionResourceList)
    const {
  for (auto& item : m_ItemList) {
    Ngap_PDUSessionResourceToReleaseItemRelCmd_t* rel =
        (Ngap_PDUSessionResourceToReleaseItemRelCmd_t*) calloc(
            1, sizeof(Ngap_PDUSessionResourceToReleaseItemRelCmd_t));
    if (!rel) return false;
    if (!item.encode(*rel)) return false;
    if (ASN_SEQUENCE_ADD(&pduSessionResourceList.list, rel) != 0) return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool PduSessionResourceToReleaseListRelCmd::decode(
    const Ngap_PDUSessionResourceToReleaseListRelCmd_t&
        pduSessionResourceList) {
  for (int i = 0; i < pduSessionResourceList.list.count; i++) {
    PduSessionResourceToReleaseItemRelCmd item = {};
    if (!item.decode(*pduSessionResourceList.list.array[i])) return false;
    m_ItemList.push_back(item);
  }
  return true;
}

}  // namespace oai::ngap
