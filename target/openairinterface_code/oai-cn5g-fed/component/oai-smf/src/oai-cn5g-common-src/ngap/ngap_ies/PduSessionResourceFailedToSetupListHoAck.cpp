/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceFailedToSetupListHoAck.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceFailedToSetupListHoAck::
    PduSessionResourceFailedToSetupListHoAck() {}

//------------------------------------------------------------------------------
PduSessionResourceFailedToSetupListHoAck::
    ~PduSessionResourceFailedToSetupListHoAck() {}

//------------------------------------------------------------------------------
void PduSessionResourceFailedToSetupListHoAck::set(
    const std::vector<PduSessionResourceItem>& list) {
  m_ItemList = list;
}

//------------------------------------------------------------------------------
void PduSessionResourceFailedToSetupListHoAck::get(
    std::vector<PduSessionResourceItem>& list) const {
  list = m_ItemList;
}

//------------------------------------------------------------------------------
bool PduSessionResourceFailedToSetupListHoAck::encode(
    Ngap_PDUSessionResourceFailedToSetupListHOAck_t& list) const {
  for (auto& item : m_ItemList) {
    Ngap_PDUSessionResourceFailedToSetupItemHOAck_t* response =
        (Ngap_PDUSessionResourceFailedToSetupItemHOAck_t*) calloc(
            1, sizeof(Ngap_PDUSessionResourceFailedToSetupItemHOAck_t));
    if (!response) return false;
    if (!item.encode(*response)) return false;
    if (ASN_SEQUENCE_ADD(&list.list, response) != 0) return false;
  }

  return true;
}

//------------------------------------------------------------------------------
bool PduSessionResourceFailedToSetupListHoAck::decode(
    const Ngap_PDUSessionResourceFailedToSetupListHOAck_t& list) {
  for (int i = 0; i < list.list.count; i++) {
    PduSessionResourceItem item = {};
    if (!item.decode(*list.list.array[i])) return false;
    m_ItemList.push_back(item);
  }

  return true;
}

}  // namespace oai::ngap
