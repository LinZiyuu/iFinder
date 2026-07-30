/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PlmnSupportList.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PlmnSupportList::PlmnSupportList() {}

//------------------------------------------------------------------------------
PlmnSupportList::~PlmnSupportList() {}

//------------------------------------------------------------------------------
bool PlmnSupportList::encode(Ngap_PLMNSupportList_t& plmnSupportList) const {
  for (std::vector<PlmnSupportItem>::const_iterator it = m_List.begin();
       it != m_List.end(); ++it) {
    Ngap_PLMNSupportItem_t* supportItem =
        (Ngap_PLMNSupportItem_t*) calloc(1, sizeof(Ngap_PLMNSupportItem_t));
    if (!supportItem) return false;
    if (!it->encode(*supportItem)) return false;
    if (ASN_SEQUENCE_ADD(&plmnSupportList.list, supportItem) != 0) return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool PlmnSupportList::decode(const Ngap_PLMNSupportList_t& plmnSupportList) {
  m_List.clear();
  for (int i = 0; i < plmnSupportList.list.count; i++) {
    PlmnSupportItem item = {};
    if (!item.decode(*plmnSupportList.list.array[i])) return false;
    m_List.push_back(item);
  }

  return true;
}

//------------------------------------------------------------------------------
void PlmnSupportList::set(const std::vector<PlmnSupportItem>& items) {
  m_List = items;
}

//------------------------------------------------------------------------------
void PlmnSupportList::get(std::vector<PlmnSupportItem>& items) const {
  items = m_List;
}

//------------------------------------------------------------------------------
void PlmnSupportList::addItem(const PlmnSupportItem& item) {
  m_List.push_back(item);
}

}  // namespace oai::ngap
