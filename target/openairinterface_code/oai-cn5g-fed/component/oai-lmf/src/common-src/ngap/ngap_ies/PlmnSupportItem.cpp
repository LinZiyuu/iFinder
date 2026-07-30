/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PlmnSupportItem.hpp"

extern "C" {
#include "Ngap_SliceSupportItem.h"
}

namespace oai::ngap {

//------------------------------------------------------------------------------
PlmnSupportItem::PlmnSupportItem() {}

//------------------------------------------------------------------------------
PlmnSupportItem::~PlmnSupportItem() {}

//------------------------------------------------------------------------------
void PlmnSupportItem::set(
    const PlmnId& plmnId, const std::vector<SNssai>& sNssais) {
  m_PlmnId           = plmnId;
  m_SliceSupportList = sNssais;
}

//------------------------------------------------------------------------------
void PlmnSupportItem::get(PlmnId& plmnId, std::vector<SNssai>& sNssais) const {
  plmnId  = m_PlmnId;
  sNssais = m_SliceSupportList;
}

//------------------------------------------------------------------------------
bool PlmnSupportItem::encode(Ngap_PLMNSupportItem_t& plmnSupportItem) const {
  if (!m_PlmnId.encode(plmnSupportItem.pLMNIdentity)) return false;
  for (std::vector<SNssai>::const_iterator it = m_SliceSupportList.begin();
       it < m_SliceSupportList.end(); ++it) {
    Ngap_SliceSupportItem_t* slice =
        (Ngap_SliceSupportItem_t*) calloc(1, sizeof(Ngap_SliceSupportItem_t));
    if (!it->encode(slice->s_NSSAI)) return false;
    ASN_SEQUENCE_ADD(&plmnSupportItem.sliceSupportList.list, slice);
  }
  return true;
}

//------------------------------------------------------------------------------
bool PlmnSupportItem::decode(const Ngap_PLMNSupportItem_t& plmnSupportItem) {
  if (!m_PlmnId.decode(plmnSupportItem.pLMNIdentity)) return false;

  for (int i = 0; i < plmnSupportItem.sliceSupportList.list.count; i++) {
    SNssai snssai = {};
    if (!snssai.decode(plmnSupportItem.sliceSupportList.list.array[i]->s_NSSAI))
      return false;
    m_SliceSupportList.push_back(snssai);
  }
  return true;
}
}  // namespace oai::ngap
