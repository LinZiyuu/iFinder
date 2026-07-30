/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "BroadcastPlmnItem.hpp"

#include "PlmnId.hpp"
#include "SNssai.hpp"

extern "C" {
#include "Ngap_BroadcastPLMNList.h"
#include "Ngap_SliceSupportItem.h"
}

namespace oai::ngap {

//------------------------------------------------------------------------------
BroadcastPlmnItem::BroadcastPlmnItem() {}

//------------------------------------------------------------------------------
BroadcastPlmnItem::~BroadcastPlmnItem() {}

//------------------------------------------------------------------------------
void BroadcastPlmnItem::set(
    const PlmnId& plmn, const std::vector<SNssai>& sliceList) {
  m_Plmn               = plmn;
  m_SupportedSliceList = sliceList;
}

//------------------------------------------------------------------------------
void BroadcastPlmnItem::get(
    PlmnId& plmn, std::vector<SNssai>& sliceList) const {
  plmn      = m_Plmn;
  sliceList = m_SupportedSliceList;
}

//------------------------------------------------------------------------------
PlmnId BroadcastPlmnItem::getPlmn() const {
  return m_Plmn;
}

//------------------------------------------------------------------------------
void BroadcastPlmnItem::setPlmn(const PlmnId& plmn) {
  m_Plmn = plmn;
}

//------------------------------------------------------------------------------
std::vector<SNssai> BroadcastPlmnItem::getSNssai() const {
  return m_SupportedSliceList;
}

//------------------------------------------------------------------------------
void BroadcastPlmnItem::setSNssai(const std::vector<SNssai>& sliceList) {
  m_SupportedSliceList = sliceList;
}

//------------------------------------------------------------------------------
void BroadcastPlmnItem::addSNssai(const SNssai snssai) {
  m_SupportedSliceList.push_back(snssai);
}

//------------------------------------------------------------------------------
bool BroadcastPlmnItem::encode(Ngap_BroadcastPLMNItem_t& plmnItem) const {
  if (!m_Plmn.encode(plmnItem.pLMNIdentity)) return false;

  for (std::vector<SNssai>::const_iterator it =
           std::begin(m_SupportedSliceList);
       it < std::end(m_SupportedSliceList); ++it) {
    Ngap_SliceSupportItem_t* slice =
        (Ngap_SliceSupportItem_t*) calloc(1, sizeof(Ngap_SliceSupportItem_t));
    if (!slice) return false;
    if (!it->encode(slice->s_NSSAI)) return false;
    if (ASN_SEQUENCE_ADD(&plmnItem.tAISliceSupportList.list, slice) != 0)
      return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool BroadcastPlmnItem::decode(const Ngap_BroadcastPLMNItem_t& pdu) {
  if (!m_Plmn.decode(pdu.pLMNIdentity)) return false;
  for (int i = 0; i < pdu.tAISliceSupportList.list.count; i++) {
    SNssai snssai = {};
    if (!snssai.decode(pdu.tAISliceSupportList.list.array[i]->s_NSSAI))
      return false;
    m_SupportedSliceList.push_back(snssai);
  }
  return true;
}

}  // namespace oai::ngap
