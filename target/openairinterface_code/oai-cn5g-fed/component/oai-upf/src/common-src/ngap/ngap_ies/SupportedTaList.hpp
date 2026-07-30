/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _SUPPORTED_TA_LIST_H_
#define _SUPPORTED_TA_LIST_H_

#include <vector>

#include "SupportedTaItem.hpp"

extern "C" {
#include "Ngap_SupportedTAList.h"
}

namespace oai::ngap {

class SupportedTaList {
 public:
  SupportedTaList();
  virtual ~SupportedTaList();

  void setSupportedTaItems(const std::vector<SupportedTaItem>& items);
  void getSupportedTaItems(std::vector<SupportedTaItem>& items) const;

  bool encode(Ngap_SupportedTAList_t& supportedTaList) const;
  bool decode(const Ngap_SupportedTAList_t& supportedTaList);

 private:
  std::vector<SupportedTaItem> m_SupportedTaItems;
};
}  // namespace oai::ngap

#endif
