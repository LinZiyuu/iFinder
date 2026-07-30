/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "SupportedTaItem.hpp"

#include "BroadcastPlmnItem.hpp"

extern "C" {
#include "Ngap_BroadcastPLMNItem.h"
#include "Ngap_SupportedTAItem.h"
}

namespace oai::ngap {

//------------------------------------------------------------------------------
SupportedTaItem::SupportedTaItem() {}

//------------------------------------------------------------------------------
SupportedTaItem::~SupportedTaItem() {}

//------------------------------------------------------------------------------
void SupportedTaItem::setTac(const TAC& m_tac) {
  m_Tac = m_tac;
}

//------------------------------------------------------------------------------
void SupportedTaItem::getTac(TAC& m_tac) const {
  m_tac = m_Tac;
}

//------------------------------------------------------------------------------
TAC SupportedTaItem::getTac() const {
  return m_Tac;
}

//------------------------------------------------------------------------------
void SupportedTaItem::setBroadcastPlmnList(
    const std::vector<BroadcastPlmnItem>& list) {
  m_BroadcastPlmnList = list;
}

//------------------------------------------------------------------------------
void SupportedTaItem::getBroadcastPlmnList(
    std::vector<BroadcastPlmnItem>& list) const {
  list = m_BroadcastPlmnList;
}

//------------------------------------------------------------------------------
std::vector<BroadcastPlmnItem> SupportedTaItem::getBroadcastPlmnList() const {
  return m_BroadcastPlmnList;
}

//------------------------------------------------------------------------------
bool SupportedTaItem::encode(Ngap_SupportedTAItem_t& ta) const {
  if (!m_Tac.encode(ta.tAC)) return false;

  for (std::vector<BroadcastPlmnItem>::const_iterator it =
           m_BroadcastPlmnList.begin();
       it < m_BroadcastPlmnList.end(); ++it) {
    Ngap_BroadcastPLMNItem_t* plmnItem =
        (Ngap_BroadcastPLMNItem*) calloc(1, sizeof(Ngap_BroadcastPLMNItem));
    if (!it->encode(*plmnItem)) return false;
    if (ASN_SEQUENCE_ADD(&ta.broadcastPLMNList.list, plmnItem) != 0)
      return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool SupportedTaItem::decode(const Ngap_SupportedTAItem_t& pdu) {
  if (!m_Tac.decode(pdu.tAC)) return false;
  for (int i = 0; i < pdu.broadcastPLMNList.list.count; i++) {
    BroadcastPlmnItem item = {};
    if (!item.decode(*pdu.broadcastPLMNList.list.array[i])) return false;
    m_BroadcastPlmnList.push_back(item);
  }
  return true;
}

}  // namespace oai::ngap
