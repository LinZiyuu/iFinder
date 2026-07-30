/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "GlobalGnbId.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
GlobalGnbId::GlobalGnbId() {
  m_PlmnId = {};
  m_GnbId  = {};
}

//------------------------------------------------------------------------------
GlobalGnbId::~GlobalGnbId() {}

//------------------------------------------------------------------------------
void GlobalGnbId::set(const PlmnId& plmn, const GnbId& gnbId) {
  m_PlmnId = plmn;
  m_GnbId  = gnbId;
}

//------------------------------------------------------------------------------
void GlobalGnbId::get(PlmnId& plmn, GnbId& gnbId) const {
  plmn  = m_PlmnId;
  gnbId = m_GnbId;
}

//------------------------------------------------------------------------------
bool GlobalGnbId::encode(Ngap_GlobalGNB_ID_t& globalGnbId) const {
  if (!m_PlmnId.encode(globalGnbId.pLMNIdentity)) return false;
  if (!m_GnbId.encode(globalGnbId.gNB_ID)) return false;

  return true;
}

//------------------------------------------------------------------------------
bool GlobalGnbId::decode(const Ngap_GlobalGNB_ID_t& globalGnbId) {
  if (!m_PlmnId.decode(globalGnbId.pLMNIdentity)) return false;
  if (!m_GnbId.decode(globalGnbId.gNB_ID)) return false;

  return true;
}
}  // namespace oai::ngap
