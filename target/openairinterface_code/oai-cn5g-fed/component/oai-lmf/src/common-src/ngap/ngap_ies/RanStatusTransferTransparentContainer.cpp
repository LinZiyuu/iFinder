/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "RanStatusTransferTransparentContainer.hpp"

#include "logger.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
RanStatusTransferTransparentContainer::RanStatusTransferTransparentContainer() {
}

//------------------------------------------------------------------------------
RanStatusTransferTransparentContainer::
    ~RanStatusTransferTransparentContainer() {}

//------------------------------------------------------------------------------
void RanStatusTransferTransparentContainer::getDrbSubjectList(
    DrbSubjectToStatusTransferList& drblist) const {
  drblist = m_DrbList;
}

//------------------------------------------------------------------------------
void RanStatusTransferTransparentContainer::setDrbSubjectList(
    const DrbSubjectToStatusTransferList& drblist) {
  m_DrbList = drblist;
}

//------------------------------------------------------------------------------
bool RanStatusTransferTransparentContainer::encode(
    Ngap_RANStatusTransfer_TransparentContainer_t& ranStatusTransfer) const {
  if (!m_DrbList.encode(ranStatusTransfer.dRBsSubjectToStatusTransferList)) {
    Logger::ngap().error(
        "Encode RANStatusTransferTransparentContainer IE error!");
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool RanStatusTransferTransparentContainer::decode(
    const Ngap_RANStatusTransfer_TransparentContainer_t& ranStatusTransfer) {
  if (!m_DrbList.decode(ranStatusTransfer.dRBsSubjectToStatusTransferList)) {
    Logger::ngap().error(
        "Decode RANStatusTransferTransparentContainer IE error!");
    return false;
  }
  return true;
}
}  // namespace oai::ngap
