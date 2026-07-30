/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "UeRadioCapabilityForPaging.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
UeRadioCapabilityForPaging::UeRadioCapabilityForPaging() {
  m_UeRadioCapabilityForPagingOfNr    = std::nullopt;
  m_UeRadioCapabilityForPagingOfEutra = std::nullopt;
}

//------------------------------------------------------------------------------
UeRadioCapabilityForPaging::~UeRadioCapabilityForPaging() {}

//------------------------------------------------------------------------------
bool UeRadioCapabilityForPaging::encode(
    Ngap_UERadioCapabilityForPaging_t& ueRadioCapabilityForPaging) const {
  if (m_UeRadioCapabilityForPagingOfNr.has_value()) {
    ueRadioCapabilityForPaging.uERadioCapabilityForPagingOfNR =
        (Ngap_UERadioCapabilityForPagingOfNR_t*) calloc(
            1, sizeof(Ngap_UERadioCapabilityForPagingOfNR_t));
    if (!m_UeRadioCapabilityForPagingOfNr.value().encode(
            *ueRadioCapabilityForPaging.uERadioCapabilityForPagingOfNR))
      return false;
  }
  if (m_UeRadioCapabilityForPagingOfEutra.has_value()) {
    ueRadioCapabilityForPaging.uERadioCapabilityForPagingOfEUTRA =
        (Ngap_UERadioCapabilityForPagingOfEUTRA_t*) calloc(
            1, sizeof(Ngap_UERadioCapabilityForPagingOfEUTRA_t));
    if (!m_UeRadioCapabilityForPagingOfEutra.value().encode(
            *ueRadioCapabilityForPaging.uERadioCapabilityForPagingOfEUTRA))
      return false;
  }

  return true;
}

//------------------------------------------------------------------------------
bool UeRadioCapabilityForPaging::decode(
    const Ngap_UERadioCapabilityForPaging_t& ueRadioCapabilityForPaging) {
  if (ueRadioCapabilityForPaging.uERadioCapabilityForPagingOfNR) {
    UeRadioCapabilityForPagingOfNr tmp = {};
    if (!tmp.decode(*ueRadioCapabilityForPaging.uERadioCapabilityForPagingOfNR))
      return false;
    m_UeRadioCapabilityForPagingOfNr =
        std::optional<UeRadioCapabilityForPagingOfNr>(tmp);
  }
  if (ueRadioCapabilityForPaging.uERadioCapabilityForPagingOfEUTRA) {
    UeRadioCapabilityForPagingOfEutra tmp = {};
    if (!tmp.decode(
            *ueRadioCapabilityForPaging.uERadioCapabilityForPagingOfEUTRA))
      return false;
    m_UeRadioCapabilityForPagingOfEutra =
        std::optional<UeRadioCapabilityForPagingOfEutra>(tmp);
  }

  return true;
}

//------------------------------------------------------------------------------
void UeRadioCapabilityForPaging::setUeRadioCapabilityForPagingOfNr(
    const OCTET_STRING_t& capability) {
  UeRadioCapabilityForPagingOfNr tmp = {};
  tmp.set(capability);
  m_UeRadioCapabilityForPagingOfNr =
      std::optional<UeRadioCapabilityForPagingOfNr>(tmp);
  m_UeRadioCapabilityForPagingOfEutra = std::nullopt;
}

//------------------------------------------------------------------------------
bool UeRadioCapabilityForPaging::getUeRadioCapabilityForPagingOfNr(
    OCTET_STRING_t& capability) const {
  if (!m_UeRadioCapabilityForPagingOfNr.has_value()) return false;
  return m_UeRadioCapabilityForPagingOfNr.value().get(capability);
}

//------------------------------------------------------------------------------
void UeRadioCapabilityForPaging::setUeRadioCapabilityForPagingOfEutra(
    const OCTET_STRING_t& capability) {
  UeRadioCapabilityForPagingOfEutra tmp = {};
  tmp.set(capability);
  m_UeRadioCapabilityForPagingOfEutra =
      std::optional<UeRadioCapabilityForPagingOfEutra>(tmp);

  m_UeRadioCapabilityForPagingOfNr = std::nullopt;
}

//------------------------------------------------------------------------------
bool UeRadioCapabilityForPaging::getUeRadioCapabilityForPagingOfEutra(
    OCTET_STRING_t& capability) const {
  if (!m_UeRadioCapabilityForPagingOfEutra.has_value()) return false;
  return m_UeRadioCapabilityForPagingOfEutra.value().get(capability);
}

}  // namespace oai::ngap
