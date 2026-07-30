/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "UlNgUUpTnlModifyItem.hpp"

#include "utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
UlNgUUpTnlModifyItem::UlNgUUpTnlModifyItem() {}

//------------------------------------------------------------------------------
UlNgUUpTnlModifyItem::~UlNgUUpTnlModifyItem() {}

//------------------------------------------------------------------------------
void UlNgUUpTnlModifyItem::set(
    const UpTransportLayerInformation& ulNgUUpTnlInformation,
    const UpTransportLayerInformation& dlNgUUpTnlInformation) {
  m_UlNgUUpTnlInformation = ulNgUUpTnlInformation;
  m_DlNgUUpTnlInformation = dlNgUUpTnlInformation;
}
//------------------------------------------------------------------------------
void UlNgUUpTnlModifyItem::get(
    UpTransportLayerInformation& ulNgUUpTnlInformation,
    UpTransportLayerInformation& dlNgUUpTnlInformation) const {
  ulNgUUpTnlInformation = m_UlNgUUpTnlInformation;
  dlNgUUpTnlInformation = m_DlNgUUpTnlInformation;
}

//------------------------------------------------------------------------------
void UlNgUUpTnlModifyItem::setUlNgUUpTnlInformation(
    const UpTransportLayerInformation& ulNgUUpTnlInformation) {
  m_UlNgUUpTnlInformation = ulNgUUpTnlInformation;
}

//------------------------------------------------------------------------------
void UlNgUUpTnlModifyItem::getUlNgUUpTnlInformation(
    UpTransportLayerInformation& ulNgUUpTnlInformation) const {
  ulNgUUpTnlInformation = m_UlNgUUpTnlInformation;
}

//------------------------------------------------------------------------------
void UlNgUUpTnlModifyItem::setDlNgUUpTnlInformation(
    const UpTransportLayerInformation& dlNgUUpTnlInformation) {
  m_DlNgUUpTnlInformation = dlNgUUpTnlInformation;
}
//------------------------------------------------------------------------------
void UlNgUUpTnlModifyItem::getDlNgUUpTnlInformation(
    UpTransportLayerInformation& dlNgUUpTnlInformation) const {
  dlNgUUpTnlInformation = m_DlNgUUpTnlInformation;
}

//------------------------------------------------------------------------------
bool UlNgUUpTnlModifyItem::encode(
    Ngap_UL_NGU_UP_TNLModifyItem_t& ulNgUUpTnlModifyItem) const {
  if (!m_UlNgUUpTnlInformation.encode(
          ulNgUUpTnlModifyItem.uL_NGU_UP_TNLInformation)) {
    return false;
  }
  if (!m_DlNgUUpTnlInformation.encode(
          ulNgUUpTnlModifyItem.dL_NGU_UP_TNLInformation)) {
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool UlNgUUpTnlModifyItem::decode(
    const Ngap_UL_NGU_UP_TNLModifyItem_t& ulNgUUpTnlModifyItem) {
  if (!m_UlNgUUpTnlInformation.decode(
          ulNgUUpTnlModifyItem.uL_NGU_UP_TNLInformation))
    false;
  if (!m_DlNgUUpTnlInformation.decode(
          ulNgUUpTnlModifyItem.dL_NGU_UP_TNLInformation))
    return false;

  return true;
}

}  // namespace oai::ngap
