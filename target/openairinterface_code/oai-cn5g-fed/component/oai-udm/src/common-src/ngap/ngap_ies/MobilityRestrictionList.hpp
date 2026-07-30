/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _MOBILITY_RESTRICTION_LIST_H_
#define _MOBILITY_RESTRICTION_LIST_H_

#include "PlmnId.hpp"

extern "C" {
#include "Ngap_MobilityRestrictionList.h"
}

namespace oai::ngap {

class MobilityRestrictionList {
 public:
  MobilityRestrictionList();
  virtual ~MobilityRestrictionList();

  void setPlmn(const PlmnId& plmn);
  void getPlmn(PlmnId& plmn) const;

  bool encode(Ngap_MobilityRestrictionList_t& mobilityRestrictionList) const;
  bool decode(const Ngap_MobilityRestrictionList_t& mobilityRestrictionList);

 private:
  PlmnId m_ServingPlmn;  // Mandatory
  // TODO: Equivalent PLMNs (optional)
  // TODO: RAT Restrictions (optional)
  // TODO: Forbidden Area Information (optional)
  // TODO: Service Area Information (optional)
  // TODO: Last E-UTRAN PLMN Identity (optional)
  // TODO: Core Network Type Restriction for Serving PLMN (optional)
  // TODO: Core Network Type Restriction for Equivalent PLMNs (optional)
};
}  // namespace oai::ngap
#endif
