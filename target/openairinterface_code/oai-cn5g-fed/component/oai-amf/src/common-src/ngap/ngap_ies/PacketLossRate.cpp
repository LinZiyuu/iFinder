/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PacketLossRate.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PacketLossRate::PacketLossRate() {
  m_PacketLossRate = 0;
}

//------------------------------------------------------------------------------
PacketLossRate::~PacketLossRate() {}

//------------------------------------------------------------------------------
void PacketLossRate::set(long value) {
  m_PacketLossRate = value;
}

//------------------------------------------------------------------------------
bool PacketLossRate::get(long& value) const {
  value = m_PacketLossRate;

  return true;
}

//------------------------------------------------------------------------------
bool PacketLossRate::encode(Ngap_PacketLossRate_t& packetLossRate) const {
  packetLossRate = m_PacketLossRate;

  return true;
}

//------------------------------------------------------------------------------
bool PacketLossRate::decode(const Ngap_PacketLossRate_t& packetLossRate) {
  m_PacketLossRate = packetLossRate;

  return true;
}
}  // namespace oai::ngap
