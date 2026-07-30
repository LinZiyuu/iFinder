/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "DrbsSubjectToStatusTransferItem.hpp"

#include "logger_base.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
DrbSubjectToStatusTransferItem::DrbSubjectToStatusTransferItem() {}

//------------------------------------------------------------------------------
DrbSubjectToStatusTransferItem::~DrbSubjectToStatusTransferItem() {}

//------------------------------------------------------------------------------
void DrbSubjectToStatusTransferItem::set(
    const Ngap_DRB_ID_t& drbId, const DrbStatusUl& drbUl,
    const DrbStatusDl& drbDl) {
  m_DrbId = drbId;
  m_DrbUl = drbUl;
  m_DrbDl = drbDl;
}

//------------------------------------------------------------------------------
void DrbSubjectToStatusTransferItem::get(
    Ngap_DRB_ID_t& drbId, DrbStatusUl& drbUl, DrbStatusDl& drbDl) const {
  drbId = m_DrbId;
  drbUl = m_DrbUl;
  drbDl = m_DrbDl;
}

//------------------------------------------------------------------------------
bool DrbSubjectToStatusTransferItem::decode(
    const Ngap_DRBsSubjectToStatusTransferItem_t& drbItem) {
  if (drbItem.dRB_ID) {
    m_DrbId = drbItem.dRB_ID;
  }
  if (!m_DrbUl.decode(drbItem.dRBStatusUL)) {
    return false;
  }
  if (!m_DrbDl.decode(drbItem.dRBStatusDL)) {
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool DrbSubjectToStatusTransferItem::encode(
    Ngap_DRBsSubjectToStatusTransferItem_t& drbItem) const {
  drbItem.dRB_ID = m_DrbId;

  if (!m_DrbUl.encode(drbItem.dRBStatusUL)) {
    return false;
  }

  if (!m_DrbDl.encode(drbItem.dRBStatusDL)) {
    return false;
  }

  oai::logger::logger_common::ngap().debug(
      "Encode from DrbSubjectToStatusTransferItem successfully");
  return true;
}
}  // namespace oai::ngap
