/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _SLICE_SUPPORT_LIST_H_
#define _SLICE_SUPPORT_LIST_H_

#include <vector>

#include "SNssai.hpp"

extern "C" {
#include "Ngap_SliceSupportList.h"
#include "Ngap_SliceSupportItem.h"
}

namespace oai::ngap {

class SliceSupportList {
 public:
  SliceSupportList();
  virtual ~SliceSupportList();

  void setSliceSupportItems(const std::vector<SNssai>& items);
  void getSliceSupportItems(std::vector<SNssai>& items) const;

  bool encode(Ngap_SliceSupportList_t& SliceSupportList) const;
  bool decode(const Ngap_SliceSupportList_t& SliceSupportList);

 private:
  std::vector<SNssai> m_SliceSupportItems;
};
}  // namespace oai::ngap

#endif
