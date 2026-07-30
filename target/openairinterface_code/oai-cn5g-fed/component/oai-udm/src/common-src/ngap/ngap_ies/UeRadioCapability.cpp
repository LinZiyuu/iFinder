/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "UeRadioCapability.hpp"

#include "ngap_utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
UeRadioCapability::UeRadioCapability() {
  m_UeRadioCapability = nullptr;
}

/*
UeRadioCapability::UeRadioCapability(const OCTET_STRING_t& capability) {
          if (!capability.buf) return;
          ngap_utils::bstring_2_octet_string(m_UeRadioCapability, capability);
}

UeRadioCapability::UeRadioCapability(const bstring& capability) {
        ngap_utils::bstring_2_octet_string(capability, m_UeRadioCapability);
}
*/
//------------------------------------------------------------------------------
UeRadioCapability::~UeRadioCapability() {}

//------------------------------------------------------------------------------
bool UeRadioCapability::encode(
    Ngap_UERadioCapability_t& ueRadioCapability) const {
  return ngap_utils::bstring_2_octet_string(
      m_UeRadioCapability, ueRadioCapability);
}

//------------------------------------------------------------------------------
bool UeRadioCapability::decode(
    const Ngap_UERadioCapability_t& ueRadioCapability) {
  if (!ueRadioCapability.buf) return false;
  return ngap_utils::octet_string_2_bstring(
      ueRadioCapability, m_UeRadioCapability);
}

//------------------------------------------------------------------------------
bool UeRadioCapability::set(const OCTET_STRING_t& capability) {
  ngap_utils::octet_string_2_bstring(capability, m_UeRadioCapability);
  return true;
}

//------------------------------------------------------------------------------
bool UeRadioCapability::get(OCTET_STRING_t& capability) const {
  ngap_utils::bstring_2_octet_string(m_UeRadioCapability, capability);
  return true;
}

//------------------------------------------------------------------------------
bool UeRadioCapability::set(const bstring& capability) {
  m_UeRadioCapability = bstrcpy(capability);
  return true;
}

//------------------------------------------------------------------------------
bool UeRadioCapability::get(bstring& capability) const {
  capability = bstrcpy(m_UeRadioCapability);
  return true;
}

}  // namespace oai::ngap
