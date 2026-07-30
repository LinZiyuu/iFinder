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
  m_PlmnId = plmnId;
  m_SliceSupportList.setSliceSupportItems(sNssais);
}

//------------------------------------------------------------------------------
void PlmnSupportItem::get(PlmnId& plmnId, std::vector<SNssai>& sNssais) const {
  plmnId = m_PlmnId;
  m_SliceSupportList.getSliceSupportItems(sNssais);
}

//------------------------------------------------------------------------------
void PlmnSupportItem::setPlmn(const PlmnId& plmnId) {
  m_PlmnId = plmnId;
}

//------------------------------------------------------------------------------
void PlmnSupportItem::getPlmn(PlmnId& plmnId) const {
  plmnId = m_PlmnId;
}

//------------------------------------------------------------------------------
void PlmnSupportItem::setSliceSupportList(
    const SliceSupportList& sliceSupportList) {
  m_SliceSupportList = sliceSupportList;
}

//------------------------------------------------------------------------------
void PlmnSupportItem::getSliceSupportList(
    SliceSupportList& sliceSupportList) const {
  sliceSupportList = m_SliceSupportList;
}

//------------------------------------------------------------------------------
bool PlmnSupportItem::encode(Ngap_PLMNSupportItem_t& plmnSupportItem) const {
  if (!m_PlmnId.encode(plmnSupportItem.pLMNIdentity)) return false;
  if (!m_SliceSupportList.encode(plmnSupportItem.sliceSupportList))
    return false;
  return true;
}

//------------------------------------------------------------------------------
bool PlmnSupportItem::decode(const Ngap_PLMNSupportItem_t& plmnSupportItem) {
  if (!m_PlmnId.decode(plmnSupportItem.pLMNIdentity)) return false;
  if (!m_SliceSupportList.decode(plmnSupportItem.sliceSupportList))
    return false;
  return true;
}
}  // namespace oai::ngap
