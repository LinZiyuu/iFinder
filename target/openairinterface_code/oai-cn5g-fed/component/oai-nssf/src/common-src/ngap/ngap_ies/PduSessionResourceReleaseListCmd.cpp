/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceReleaseListCmd.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceReleaseListCmd::PduSessionResourceReleaseListCmd() {}

//------------------------------------------------------------------------------
PduSessionResourceReleaseListCmd::~PduSessionResourceReleaseListCmd() {}

//------------------------------------------------------------------------------
void PduSessionResourceReleaseListCmd::set(
    const std::vector<PduSessionResourceReleaseItemCmd>& itemList) {
  uint8_t number_items = (itemList.size() > kMaxNoOfPduSessions) ?
                             kMaxNoOfPduSessions :
                             itemList.size();
  m_ItemList.insert(
      m_ItemList.begin(), itemList.begin(), itemList.begin() + number_items);
}

//------------------------------------------------------------------------------
void PduSessionResourceReleaseListCmd::get(
    std::vector<PduSessionResourceReleaseItemCmd>& itemList) const {
  itemList = m_ItemList;
}

//------------------------------------------------------------------------------
bool PduSessionResourceReleaseListCmd::encode(
    Ngap_PDUSessionResourceToReleaseListRelCmd_t&
        pduSessionResourceReleaseListCmd) const {
  for (int i = 0; i < m_ItemList.size(); i++) {
    Ngap_PDUSessionResourceToReleaseItemRelCmd_t* item =
        (Ngap_PDUSessionResourceToReleaseItemRelCmd_t*) calloc(
            1, sizeof(Ngap_PDUSessionResourceToReleaseItemRelCmd_t));
    if (!item) return false;
    if (!m_ItemList[i].encode(*item)) return false;
    if (ASN_SEQUENCE_ADD(&pduSessionResourceReleaseListCmd.list, item) != 0)
      return false;
  }

  return true;
}

//------------------------------------------------------------------------------
bool PduSessionResourceReleaseListCmd::decode(
    const Ngap_PDUSessionResourceToReleaseListRelCmd_t&
        pduSessionResourceReleaseListCmd) {
  for (int i = 0; i < pduSessionResourceReleaseListCmd.list.count; i++) {
    PduSessionResourceReleaseItemCmd item = {};
    if (!item.decode(*pduSessionResourceReleaseListCmd.list.array[i]))
      return false;
    m_ItemList.push_back(item);
  }

  return true;
}
}  // namespace oai::ngap
