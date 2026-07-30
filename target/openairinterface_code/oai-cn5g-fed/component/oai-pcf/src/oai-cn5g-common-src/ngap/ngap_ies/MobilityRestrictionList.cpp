/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "MobilityRestrictionList.hpp"

namespace oai::ngap {
//------------------------------------------------------------------------------
MobilityRestrictionList::MobilityRestrictionList() {}
//------------------------------------------------------------------------------
MobilityRestrictionList::~MobilityRestrictionList() {}

//------------------------------------------------------------------------------
void MobilityRestrictionList::setPlmn(const PlmnId& plmn) {
  m_ServingPlmn = plmn;
}

//------------------------------------------------------------------------------
void MobilityRestrictionList::getPlmn(PlmnId& plmn) const {
  plmn = m_ServingPlmn;
}

//------------------------------------------------------------------------------
bool MobilityRestrictionList::encode(
    Ngap_MobilityRestrictionList_t& mobilityRestrictionList) const {
  if (!m_ServingPlmn.encode(mobilityRestrictionList.servingPLMN)) {
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool MobilityRestrictionList::decode(
    const Ngap_MobilityRestrictionList_t& mobilityRestrictionList) {
  if (!m_ServingPlmn.decode(mobilityRestrictionList.servingPLMN)) {
    return false;
  }
  return true;
}
}  // namespace oai::ngap
