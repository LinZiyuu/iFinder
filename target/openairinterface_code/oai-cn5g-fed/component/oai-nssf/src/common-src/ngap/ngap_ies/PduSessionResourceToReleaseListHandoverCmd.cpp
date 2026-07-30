/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceToReleaseListHandoverCmd.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceToReleaseListHandoverCmd::
    PduSessionResourceToReleaseListHandoverCmd() {}

//------------------------------------------------------------------------------
PduSessionResourceToReleaseListHandoverCmd::
    ~PduSessionResourceToReleaseListHandoverCmd() {}

//------------------------------------------------------------------------------
void PduSessionResourceToReleaseListHandoverCmd::set(
    const std::vector<PduSessionResourceItem>& list) {
  m_ItemList = list;
}

//------------------------------------------------------------------------------
void PduSessionResourceToReleaseListHandoverCmd::get(
    std::vector<PduSessionResourceItem>& list) const {
  list = m_ItemList;
}

//------------------------------------------------------------------------------
bool PduSessionResourceToReleaseListHandoverCmd::encode(
    Ngap_PDUSessionResourceToReleaseListHOCmd_t& list) const {
  for (auto& item : m_ItemList) {
    Ngap_PDUSessionResourceToReleaseItemHOCmd_t* rel =
        (Ngap_PDUSessionResourceToReleaseItemHOCmd_t*) calloc(
            1, sizeof(Ngap_PDUSessionResourceToReleaseItemHOCmd_t));
    if (!rel) return false;
    if (!item.encode(*rel)) return false;
    if (ASN_SEQUENCE_ADD(&list.list, rel) != 0) return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool PduSessionResourceToReleaseListHandoverCmd::decode(
    const Ngap_PDUSessionResourceToReleaseListHOCmd_t& list) {
  for (int i = 0; i < list.list.count; i++) {
    PduSessionResourceItem item = {};
    if (!item.decode(*list.list.array[i])) return false;
    m_ItemList.push_back(item);
  }
  return true;
}

}  // namespace oai::ngap
