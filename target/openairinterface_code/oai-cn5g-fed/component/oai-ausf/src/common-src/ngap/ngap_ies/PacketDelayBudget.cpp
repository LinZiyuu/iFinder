/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PacketDelayBudget.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PacketDelayBudget::PacketDelayBudget() {
  m_PacketDelayBudget = 0;
}

//------------------------------------------------------------------------------
PacketDelayBudget::~PacketDelayBudget() {}

//------------------------------------------------------------------------------
void PacketDelayBudget::set(const long& value) {
  m_PacketDelayBudget = value;
}

//------------------------------------------------------------------------------
bool PacketDelayBudget::get(long& value) const {
  value = m_PacketDelayBudget;

  return true;
}

//------------------------------------------------------------------------------
bool PacketDelayBudget::encode(Ngap_PacketDelayBudget_t& value) const {
  value = m_PacketDelayBudget;

  return true;
}

//------------------------------------------------------------------------------
bool PacketDelayBudget::decode(const Ngap_PacketDelayBudget_t& value) {
  m_PacketDelayBudget = value;

  return true;
}
}  // namespace oai::ngap
