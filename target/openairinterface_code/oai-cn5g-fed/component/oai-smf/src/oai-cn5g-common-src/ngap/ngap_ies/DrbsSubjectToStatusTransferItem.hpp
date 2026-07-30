/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _DRBS_SUBJECT_TO_STATUS_TRANSFERT_ITEM_H_
#define _DRBS_SUBJECT_TO_STATUS_TRANSFERT_ITEM_H_

#include "DrbStatusDl.hpp"
#include "DrbStatusUl.hpp"

extern "C" {
#include "Ngap_DRBsSubjectToStatusTransferItem.h"
}

namespace oai::ngap {

class DrbSubjectToStatusTransferItem {
 public:
  DrbSubjectToStatusTransferItem();
  virtual ~DrbSubjectToStatusTransferItem();

  void get(Ngap_DRB_ID_t& drbId, DrbStatusUl& drbUl, DrbStatusDl& drbDl) const;
  void set(
      const Ngap_DRB_ID_t& drbId, const DrbStatusUl& drbUl,
      const DrbStatusDl& drbDl);

  bool encode(Ngap_DRBsSubjectToStatusTransferItem_t& drbItem) const;
  bool decode(const Ngap_DRBsSubjectToStatusTransferItem_t& drbItem);

 private:
  Ngap_DRB_ID_t m_DrbId;  // Mandatory
  DrbStatusUl m_DrbUl;    // Mandatory
  DrbStatusDl m_DrbDl;    // Mandatory
  // TODO: Old Associated QoS Flow List - UL End Marker Expected
};
}  // namespace oai::ngap
#endif
