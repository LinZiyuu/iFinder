/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PLMN_SUPPORT_ITEM_H_
#define _PLMN_SUPPORT_ITEM_H_

#include <vector>

#include "PlmnId.hpp"
#include "SNssai.hpp"

extern "C" {
#include "Ngap_PLMNSupportItem.h"
}

namespace oai::ngap {

class PlmnSupportItem {
 public:
  PlmnSupportItem();
  virtual ~PlmnSupportItem();

  void set(const PlmnId& plmnId, const std::vector<SNssai>& sNssais);
  void get(PlmnId& plmnId, std::vector<SNssai>& sNssais) const;

  bool encode(Ngap_PLMNSupportItem_t&) const;
  bool decode(const Ngap_PLMNSupportItem_t&);

 private:
  PlmnId m_PlmnId;                         // Mandatory
  std::vector<SNssai> m_SliceSupportList;  // Mandatory
};

}  // namespace oai::ngap

#endif
