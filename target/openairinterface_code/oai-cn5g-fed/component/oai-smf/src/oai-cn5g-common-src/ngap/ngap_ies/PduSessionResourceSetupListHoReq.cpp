/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceSetupListHoReq.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceSetupListHoReq::PduSessionResourceSetupListHoReq() {}

//------------------------------------------------------------------------------
PduSessionResourceSetupListHoReq::~PduSessionResourceSetupListHoReq() {}

//------------------------------------------------------------------------------
void PduSessionResourceSetupListHoReq::set(
    const std::vector<PduSessionResourceSetupItemHoReq>& list) {
  m_ItemList = list;
}

//------------------------------------------------------------------------------
void PduSessionResourceSetupListHoReq::get(
    std::vector<PduSessionResourceSetupItemHoReq>& list) const {
  list = m_ItemList;
}

//------------------------------------------------------------------------------
bool PduSessionResourceSetupListHoReq::encode(
    Ngap_PDUSessionResourceSetupListHOReq_t& resourceList) const {
  for (auto item : m_ItemList) {
    Ngap_PDUSessionResourceSetupItemHOReq_t* request =
        (Ngap_PDUSessionResourceSetupItemHOReq_t*) calloc(
            1, sizeof(Ngap_PDUSessionResourceSetupItemHOReq_t));
    if (!request) return false;
    if (!item.encode(*request)) return false;
    if (ASN_SEQUENCE_ADD(&resourceList.list, request) != 0) return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool PduSessionResourceSetupListHoReq::decode(
    const Ngap_PDUSessionResourceSetupListHOReq_t& resourceList) {
  for (int i = 0; i < resourceList.list.count; i++) {
    PduSessionResourceSetupItemHoReq item = {};
    if (!item.decode(*resourceList.list.array[i])) return false;
    m_ItemList.push_back(item);
  }
  return true;
}

}  // namespace oai::ngap
