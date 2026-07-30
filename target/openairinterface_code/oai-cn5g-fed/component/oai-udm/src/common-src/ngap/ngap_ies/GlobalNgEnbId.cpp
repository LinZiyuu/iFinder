/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "GlobalNgEnbId.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
GlobalNgEnbId::GlobalNgEnbId() {}

//------------------------------------------------------------------------------
GlobalNgEnbId::~GlobalNgEnbId() {}

//------------------------------------------------------------------------------
void GlobalNgEnbId::set(const PlmnId& plmnId, const NgEnbId& ngEnbId) {
  m_PlmnId  = plmnId;
  m_NgEnbId = ngEnbId;
}

//------------------------------------------------------------------------------
void GlobalNgEnbId::get(PlmnId& plmnId, NgEnbId& ngEnbId) const {
  plmnId  = m_PlmnId;
  ngEnbId = m_NgEnbId;
}

//------------------------------------------------------------------------------
bool GlobalNgEnbId::encode(Ngap_GlobalNgENB_ID_t& globalNgEnbId) const {
  if (!m_PlmnId.encode(globalNgEnbId.pLMNIdentity)) return false;
  if (!m_NgEnbId.encode(globalNgEnbId.ngENB_ID)) return false;
  return true;
}

//------------------------------------------------------------------------------
bool GlobalNgEnbId::decode(const Ngap_GlobalNgENB_ID_t& globalNgEnbId) {
  if (!m_PlmnId.decode(globalNgEnbId.pLMNIdentity)) return false;
  if (!m_NgEnbId.decode(globalNgEnbId.ngENB_ID)) return false;
  return true;
}
}  // namespace oai::ngap
