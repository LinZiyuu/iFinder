/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "EutraCgi.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
EutraCgi::EutraCgi() {}

//------------------------------------------------------------------------------
EutraCgi::~EutraCgi() {}

//------------------------------------------------------------------------------
void EutraCgi::set(
    const PlmnId& plmnId, const EutraCellIdentity& eutraCellIdentity) {
  m_PlmnId            = plmnId;
  m_eutraCellIdentity = eutraCellIdentity;
}

//------------------------------------------------------------------------------
void EutraCgi::get(PlmnId& plmnId, EutraCellIdentity& eutraCellIdentity) const {
  plmnId            = m_PlmnId;
  eutraCellIdentity = m_eutraCellIdentity;
}

//------------------------------------------------------------------------------
bool EutraCgi::encode(Ngap_EUTRA_CGI_t& eutraCgi) const {
  if (!m_PlmnId.encode(eutraCgi.pLMNIdentity)) return false;
  if (!m_eutraCellIdentity.encode(eutraCgi.eUTRACellIdentity)) return false;

  return true;
}

//------------------------------------------------------------------------------
bool EutraCgi::decode(const Ngap_EUTRA_CGI_t& eutraCgi) {
  if (!m_PlmnId.decode(eutraCgi.pLMNIdentity)) return false;
  if (!m_eutraCellIdentity.decode(eutraCgi.eUTRACellIdentity)) return false;
  return true;
}

}  // namespace oai::ngap
