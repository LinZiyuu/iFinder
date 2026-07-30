/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "UePagingIdentity.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
UePagingIdentity::UePagingIdentity() {}

//------------------------------------------------------------------------------
UePagingIdentity::~UePagingIdentity() {}

//------------------------------------------------------------------------------
void UePagingIdentity::set(
    const std::string& set_id, const std::string& pointer,
    const std::string& tmsi) {
  m_FiveGSTmsi.set(set_id, pointer, tmsi);
}

//------------------------------------------------------------------------------
void UePagingIdentity::get(std::string& fiveGsTmsi) const {
  m_FiveGSTmsi.getTmsi(fiveGsTmsi);
}

//------------------------------------------------------------------------------
void UePagingIdentity::get(
    std::string& set_id, std::string& pointer, std::string& tmsi) const {
  m_FiveGSTmsi.get(set_id, pointer, tmsi);
}

//------------------------------------------------------------------------------
bool UePagingIdentity::encode(Ngap_UEPagingIdentity_t& pdu) const {
  pdu.present = Ngap_UEPagingIdentity_PR_fiveG_S_TMSI;
  Ngap_FiveG_S_TMSI_t* ie =
      (Ngap_FiveG_S_TMSI_t*) calloc(1, sizeof(Ngap_FiveG_S_TMSI_t));
  pdu.choice.fiveG_S_TMSI = ie;
  if (!m_FiveGSTmsi.encode(*pdu.choice.fiveG_S_TMSI)) return false;

  return true;
}

//------------------------------------------------------------------------------
bool UePagingIdentity::decode(const Ngap_UEPagingIdentity_t& pdu) {
  if (pdu.present != Ngap_UEPagingIdentity_PR_fiveG_S_TMSI) return false;
  if (!m_FiveGSTmsi.decode(*pdu.choice.fiveG_S_TMSI)) return false;

  return true;
}
}  // namespace oai::ngap
