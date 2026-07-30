/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "ServedGuamiList.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
ServedGuamiList::ServedGuamiList() {}

//------------------------------------------------------------------------------
ServedGuamiList::~ServedGuamiList() {}

//------------------------------------------------------------------------------
void ServedGuamiList::set(const std::vector<ServedGuamiItem>& list) {
  m_ItemList = list;
}

//------------------------------------------------------------------------------
void ServedGuamiList::get(std::vector<ServedGuamiItem>& list) const {
  list = m_ItemList;
}

//------------------------------------------------------------------------------
void ServedGuamiList::addItem(const ServedGuamiItem& item) {
  m_ItemList.push_back(item);
}

//------------------------------------------------------------------------------
bool ServedGuamiList::encode(Ngap_ServedGUAMIList_t& servedGUAMIList) const {
  for (std::vector<ServedGuamiItem>::const_iterator it = m_ItemList.begin();
       it != m_ItemList.end(); ++it) {
    Ngap_ServedGUAMIItem* guamiItem =
        (Ngap_ServedGUAMIItem*) calloc(1, sizeof(Ngap_ServedGUAMIItem));
    if (!guamiItem) return false;
    if (!it->encode(*guamiItem)) return false;
    if (ASN_SEQUENCE_ADD(&servedGUAMIList.list, guamiItem) != 0) return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool ServedGuamiList::decode(const Ngap_ServedGUAMIList_t& pdu) {
  m_ItemList.clear();
  for (int i = 0; i < pdu.list.count; i++) {
    ServedGuamiItem item = {};
    if (item.decode(*pdu.list.array[i])) return false;
    m_ItemList.push_back(item);
  }
  return true;
}

}  // namespace oai::ngap
