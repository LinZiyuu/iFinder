/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "Tai.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
Tai::Tai() {}

//------------------------------------------------------------------------------
Tai::~Tai() {}

//------------------------------------------------------------------------------
void Tai::set(const PlmnId& plmnId, const TAC& tac) {
  m_PlmnId = plmnId;
  m_Tac    = tac;
}

//------------------------------------------------------------------------------
void Tai::set(
    const std::string& mcc, const std::string& mnc, const uint32_t& tac) {
  m_PlmnId.set(mcc, mnc);
  m_Tac.set(tac);
}

//------------------------------------------------------------------------------
void Tai::get(std::string& mcc, std::string& mnc, uint32_t& tac) {
  m_PlmnId.getMcc(mcc);
  m_PlmnId.getMnc(mnc);
  tac = m_Tac.get();
}

//------------------------------------------------------------------------------
void Tai::set(const Tai_t& tai) {
  m_PlmnId.set(tai.mcc, tai.mnc);
  m_Tac.set(tai.tac);
}
//------------------------------------------------------------------------------
bool Tai::encode(Ngap_TAI_t& tai) const {
  if (!m_PlmnId.encode(tai.pLMNIdentity)) return false;
  if (!m_Tac.encode(tai.tAC)) return false;

  return true;
}

//------------------------------------------------------------------------------
bool Tai::decode(const Ngap_TAI_t& tai) {
  if (!m_PlmnId.decode(tai.pLMNIdentity)) return false;
  if (!m_Tac.decode(tai.tAC)) return false;

  return true;
}

//------------------------------------------------------------------------------
void Tai::get(PlmnId& plmnId, TAC& tac) {
  plmnId = m_PlmnId;
  tac    = m_Tac;
}

//------------------------------------------------------------------------------
void Tai::get(Tai_t& tai) {
  m_PlmnId.getMcc(tai.mcc);
  m_PlmnId.getMnc(tai.mnc);
  tai.tac = m_Tac.get();
}
}  // namespace oai::ngap
