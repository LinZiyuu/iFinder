/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "TaiListforPaging.hpp"

extern "C" {
#include "Ngap_TAIListForPagingItem.h"
}

namespace oai::ngap {

//------------------------------------------------------------------------------
TaiListForPaging::TaiListForPaging() {}

//------------------------------------------------------------------------------
TaiListForPaging::~TaiListForPaging() {}

//------------------------------------------------------------------------------
void TaiListForPaging::set(const std::vector<Tai>& list) {
  m_TaiList = list;
}

//------------------------------------------------------------------------------
void TaiListForPaging::get(std::vector<Tai>& list) const {
  list = m_TaiList;
}
//------------------------------------------------------------------------------
bool TaiListForPaging::encode(Ngap_TAIListForPaging_t& pdu) const {
  for (auto& tai : m_TaiList) {
    Ngap_TAIListForPagingItem_t* ta = (Ngap_TAIListForPagingItem_t*) calloc(
        1, sizeof(Ngap_TAIListForPagingItem_t));
    if (!tai.encode(ta->tAI)) return false;
    if (ASN_SEQUENCE_ADD(&pdu.list, ta) != 0) return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool TaiListForPaging::decode(const Ngap_TAIListForPaging_t& pdu) {
  if (pdu.list.count < 0) return false;
  for (int i = 0; i < pdu.list.count; i++) {
    Tai tai = {};
    if (!tai.decode(pdu.list.array[i]->tAI)) return false;
    m_TaiList.push_back(tai);
  }

  return true;
}
}  // namespace oai::ngap
