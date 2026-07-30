/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "UeRetentionInformation.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
UeRetentionInformation::UeRetentionInformation() {
  m_UeRetentionInformation = Ngap_UERetentionInformation_ues_retained;
}

//------------------------------------------------------------------------------
UeRetentionInformation::~UeRetentionInformation() {}

//------------------------------------------------------------------------------
void UeRetentionInformation::set(const long value) {
  m_UeRetentionInformation = value;
}

//------------------------------------------------------------------------------
void UeRetentionInformation::get(long& value) const {
  value = m_UeRetentionInformation;
}

//------------------------------------------------------------------------------
void UeRetentionInformation::set(const e_Ngap_UERetentionInformation& value) {
  m_UeRetentionInformation = static_cast<long>(value);
}

//------------------------------------------------------------------------------
void UeRetentionInformation::get(e_Ngap_UERetentionInformation& value) const {
  value = static_cast<e_Ngap_UERetentionInformation>(m_UeRetentionInformation);
}

//------------------------------------------------------------------------------
e_Ngap_UERetentionInformation UeRetentionInformation::get() const {
  return static_cast<e_Ngap_UERetentionInformation>(m_UeRetentionInformation);
}

//------------------------------------------------------------------------------
bool UeRetentionInformation::encode(
    Ngap_UERetentionInformation_t& value) const {
  value = m_UeRetentionInformation;
  return true;
}

//------------------------------------------------------------------------------
bool UeRetentionInformation::decode(Ngap_UERetentionInformation_t value) {
  m_UeRetentionInformation = value;
  return true;
}

}  // namespace oai::ngap
