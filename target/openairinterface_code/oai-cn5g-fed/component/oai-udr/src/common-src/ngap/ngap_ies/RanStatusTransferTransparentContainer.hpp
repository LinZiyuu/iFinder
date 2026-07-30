/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _RAN_STATUS_TRANSFER_TRANSPARENT_CONTAINER_H_
#define _RAN_STATUS_TRANSFER_TRANSPARENT_CONTAINER_H_

#include "DrbsSubjectToStatusTransferList.hpp"

extern "C" {
#include "Ngap_RANStatusTransfer-TransparentContainer.h"
}

namespace oai::ngap {

class RanStatusTransferTransparentContainer {
 public:
  RanStatusTransferTransparentContainer();
  virtual ~RanStatusTransferTransparentContainer();

  void getDrbSubjectList(DrbSubjectToStatusTransferList& drblist) const;
  void setDrbSubjectList(const DrbSubjectToStatusTransferList& drblist);

  bool encode(
      Ngap_RANStatusTransfer_TransparentContainer_t& ranStatusTransfer) const;
  bool decode(
      const Ngap_RANStatusTransfer_TransparentContainer_t& ranStatusTransfer);

 private:
  DrbSubjectToStatusTransferList m_DrbList;  // Mandatory
};

}  // namespace oai::ngap
#endif
