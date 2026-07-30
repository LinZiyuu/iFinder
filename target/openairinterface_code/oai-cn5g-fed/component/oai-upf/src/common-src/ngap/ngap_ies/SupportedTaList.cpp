/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "SupportedTaList.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
SupportedTaList::SupportedTaList() {}

//------------------------------------------------------------------------------
SupportedTaList::~SupportedTaList() {}

//------------------------------------------------------------------------------
bool SupportedTaList::encode(Ngap_SupportedTAList_t& supportedTaList) const {
  for (std::vector<SupportedTaItem>::const_iterator it =
           m_SupportedTaItems.begin();
       it < m_SupportedTaItems.end(); ++it) {
    Ngap_SupportedTAItem_t* ta =
        (Ngap_SupportedTAItem_t*) calloc(1, sizeof(Ngap_SupportedTAItem_t));
    if (!it->encode(*ta)) return false;
    if (ASN_SEQUENCE_ADD(&supportedTaList.list, ta) != 0) return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool SupportedTaList::decode(const Ngap_SupportedTAList_t& supportedTaList) {
  for (int i = 0; i < supportedTaList.list.count; i++) {
    SupportedTaItem item = {};
    if (!item.decode(*supportedTaList.list.array[i])) return false;
    m_SupportedTaItems.push_back(item);
  }

  return true;
}

//------------------------------------------------------------------------------
void SupportedTaList::setSupportedTaItems(
    const std::vector<SupportedTaItem>& items) {
  m_SupportedTaItems = items;
}

//------------------------------------------------------------------------------
void SupportedTaList::getSupportedTaItems(
    std::vector<SupportedTaItem>& items) const {
  items = m_SupportedTaItems;
}

}  // namespace oai::ngap
