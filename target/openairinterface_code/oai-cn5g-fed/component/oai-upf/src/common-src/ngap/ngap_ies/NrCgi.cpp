/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "NrCgi.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
NrCgi::NrCgi() {}

//------------------------------------------------------------------------------
NrCgi::~NrCgi() {}

//------------------------------------------------------------------------------
void NrCgi::set(const PlmnId& plmnId, const NrCellIdentity& nrCellIdentity) {
  m_PlmnId         = plmnId;
  m_NrCellIdentity = nrCellIdentity;
}

//------------------------------------------------------------------------------
void NrCgi::set(
    const std::string& mcc, const std::string& mnc,
    const uint64_t& nrCellIdentity) {
  m_PlmnId.set(mcc, mnc);
  m_NrCellIdentity.set(nrCellIdentity);
}

//------------------------------------------------------------------------------
void NrCgi::set(const struct NrCgi_s& cig) {
  m_PlmnId.set(cig.mcc, cig.mnc);
  m_NrCellIdentity.set(cig.nrCellId);
}

//------------------------------------------------------------------------------
void NrCgi::get(struct NrCgi_s& cig) const {
  m_PlmnId.getMcc(cig.mcc);
  m_PlmnId.getMnc(cig.mnc);
  cig.nrCellId = m_NrCellIdentity.get();
}

//------------------------------------------------------------------------------
bool NrCgi::encode(Ngap_NR_CGI_t& nrCgi) const {
  if (!m_PlmnId.encode(nrCgi.pLMNIdentity)) return false;
  if (!m_NrCellIdentity.encode(nrCgi.nRCellIdentity)) return false;

  return true;
}

//------------------------------------------------------------------------------
bool NrCgi::decode(const Ngap_NR_CGI_t& nrCgi) {
  if (!m_PlmnId.decode(nrCgi.pLMNIdentity)) return false;
  if (!m_NrCellIdentity.decode(nrCgi.nRCellIdentity)) return false;
  return true;
}

//------------------------------------------------------------------------------
void NrCgi::get(PlmnId& plmnId, NrCellIdentity& nrCellIdentity) const {
  plmnId         = m_PlmnId;
  nrCellIdentity = m_NrCellIdentity;
}
}  // namespace oai::ngap
