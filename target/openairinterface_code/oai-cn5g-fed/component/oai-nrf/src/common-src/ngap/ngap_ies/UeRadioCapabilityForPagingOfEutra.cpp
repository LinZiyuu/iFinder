/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "UeRadioCapabilityForPagingOfEutra.hpp"

#include "ngap_utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
UeRadioCapabilityForPagingOfEutra::UeRadioCapabilityForPagingOfEutra() {}

//------------------------------------------------------------------------------
UeRadioCapabilityForPagingOfEutra::~UeRadioCapabilityForPagingOfEutra() {}

//------------------------------------------------------------------------------
bool UeRadioCapabilityForPagingOfEutra::encode(
    Ngap_UERadioCapabilityForPagingOfEUTRA_t& ueRadioCapabilityForPagingOfEutra)
    const {
  return ngap_utils::octet_string_copy(
      ueRadioCapabilityForPagingOfEutra, m_UeRadioCapability);
}

//------------------------------------------------------------------------------
bool UeRadioCapabilityForPagingOfEutra::decode(
    const Ngap_UERadioCapabilityForPagingOfEUTRA_t&
        ueRadioCapabilityForPagingOfEutra) {
  return ngap_utils::octet_string_copy(
      m_UeRadioCapability, ueRadioCapabilityForPagingOfEutra);
}

//------------------------------------------------------------------------------
bool UeRadioCapabilityForPagingOfEutra::set(const OCTET_STRING_t& capability) {
  return ngap_utils::octet_string_copy(m_UeRadioCapability, capability);
}

//------------------------------------------------------------------------------
bool UeRadioCapabilityForPagingOfEutra::get(OCTET_STRING_t& capability) const {
  return ngap_utils::octet_string_copy(capability, m_UeRadioCapability);
}

//------------------------------------------------------------------------------
bool UeRadioCapabilityForPagingOfEutra::set(const bstring& capability) {
  return ngap_utils::bstring_2_octet_string(capability, m_UeRadioCapability);
}

//------------------------------------------------------------------------------
bool UeRadioCapabilityForPagingOfEutra::get(bstring& capability) const {
  return ngap_utils::octet_string_2_bstring(m_UeRadioCapability, capability);
}

}  // namespace oai::ngap
