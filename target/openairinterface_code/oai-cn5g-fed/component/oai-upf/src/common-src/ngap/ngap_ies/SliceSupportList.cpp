/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "SliceSupportList.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
SliceSupportList::SliceSupportList() {}

//------------------------------------------------------------------------------
SliceSupportList::~SliceSupportList() {}

//------------------------------------------------------------------------------
bool SliceSupportList::encode(Ngap_SliceSupportList_t& SliceSupportList) const {
  for (std::vector<SNssai>::const_iterator it = m_SliceSupportItems.begin();
       it < m_SliceSupportItems.end(); ++it) {
    Ngap_SliceSupportItem_t* ta =
        (Ngap_SliceSupportItem_t*) calloc(1, sizeof(Ngap_SliceSupportItem_t));
    if (!it->encode(ta->s_NSSAI)) return false;
    if (ASN_SEQUENCE_ADD(&SliceSupportList.list, ta) != 0) return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool SliceSupportList::decode(const Ngap_SliceSupportList_t& SliceSupportList) {
  for (int i = 0; i < SliceSupportList.list.count; i++) {
    SNssai item = {};
    if (!item.decode(SliceSupportList.list.array[i]->s_NSSAI)) return false;
    m_SliceSupportItems.push_back(item);
  }

  return true;
}

//------------------------------------------------------------------------------
void SliceSupportList::setSliceSupportItems(const std::vector<SNssai>& items) {
  m_SliceSupportItems = items;
}

//------------------------------------------------------------------------------
void SliceSupportList::getSliceSupportItems(std::vector<SNssai>& items) const {
  items = m_SliceSupportItems;
}

}  // namespace oai::ngap
