/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _DRBS_SUBJECT_TO_STATUS_TRANSFER_LIST_H_
#define _DRBS_SUBJECT_TO_STATUS_TRANSFER_LIST_H_

#include <vector>

#include "DrbsSubjectToStatusTransferItem.hpp"

extern "C" {
#include "Ngap_DRBsSubjectToStatusTransferList.h"
}

namespace oai::ngap {
class DrbSubjectToStatusTransferList {
 public:
  DrbSubjectToStatusTransferList();
  virtual ~DrbSubjectToStatusTransferList();

  void set(const std::vector<DrbSubjectToStatusTransferItem>& list);
  void get(std::vector<DrbSubjectToStatusTransferItem>& list) const;

  bool encode(Ngap_DRBsSubjectToStatusTransferList_t&
                  drbsSubjectToStatusTransferList) const;
  bool decode(const Ngap_DRBsSubjectToStatusTransferList_t&
                  drbsSubjectToStatusTransferList);

 private:
  std::vector<DrbSubjectToStatusTransferItem> m_ItemList;
};
}  // namespace oai::ngap
#endif
