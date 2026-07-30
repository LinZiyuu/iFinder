/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "UeRadioCapabilityForPagingOfNr.hpp"

#include "ngap_utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
UeRadioCapabilityForPagingOfNr::UeRadioCapabilityForPagingOfNr() {}

//------------------------------------------------------------------------------
UeRadioCapabilityForPagingOfNr::~UeRadioCapabilityForPagingOfNr() {}

//------------------------------------------------------------------------------
bool UeRadioCapabilityForPagingOfNr::encode(
    Ngap_UERadioCapabilityForPagingOfNR_t& ueRadioCapabilityForPagingOfNr)
    const {
  return ngap_utils::octet_string_copy(
      ueRadioCapabilityForPagingOfNr, m_UeRadioCapability);
}

//------------------------------------------------------------------------------
bool UeRadioCapabilityForPagingOfNr::decode(
    const Ngap_UERadioCapabilityForPagingOfNR_t&
        ueRadioCapabilityForPagingOfNr) {
  return ngap_utils::octet_string_copy(
      m_UeRadioCapability, ueRadioCapabilityForPagingOfNr);
}

//------------------------------------------------------------------------------
bool UeRadioCapabilityForPagingOfNr::set(const OCTET_STRING_t& capability) {
  return ngap_utils::octet_string_copy(m_UeRadioCapability, capability);
}

//------------------------------------------------------------------------------
bool UeRadioCapabilityForPagingOfNr::get(OCTET_STRING_t& capability) const {
  return ngap_utils::octet_string_copy(capability, m_UeRadioCapability);
}

//------------------------------------------------------------------------------
bool UeRadioCapabilityForPagingOfNr::set(const bstring& capability) {
  return ngap_utils::bstring_2_octet_string(capability, m_UeRadioCapability);
}

//------------------------------------------------------------------------------
bool UeRadioCapabilityForPagingOfNr::get(bstring& capability) const {
  return ngap_utils::octet_string_2_bstring(m_UeRadioCapability, capability);
}

}  // namespace oai::ngap
