/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "NetworkInstance.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
NetworkInstance::NetworkInstance() {
  m_NetworkInstance = 0;
}

//------------------------------------------------------------------------------
NetworkInstance::NetworkInstance(const long& networkInstance) {
  m_NetworkInstance = networkInstance;
}
//------------------------------------------------------------------------------
NetworkInstance::~NetworkInstance() {}

//------------------------------------------------------------------------------
void NetworkInstance::set(const long& networkInstance) {
  m_NetworkInstance = networkInstance;
}

//------------------------------------------------------------------------------
bool NetworkInstance::get(long& networkInstance) const {
  networkInstance = m_NetworkInstance;

  return true;
}

//------------------------------------------------------------------------------
bool NetworkInstance::encode(Ngap_NetworkInstance_t& value) const {
  value = m_NetworkInstance;

  return true;
}

//------------------------------------------------------------------------------
bool NetworkInstance::decode(const Ngap_NetworkInstance_t& value) {
  m_NetworkInstance = value;

  return true;
}

}  // namespace oai::ngap
