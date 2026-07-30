/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PacketErrorRate.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PacketErrorRate::PacketErrorRate() {
  m_Scalar   = 0;
  m_Exponent = 0;
}

//------------------------------------------------------------------------------
PacketErrorRate::~PacketErrorRate() {}

//------------------------------------------------------------------------------
void PacketErrorRate::set(const long& scalar, const long& exponent) {
  m_Scalar   = scalar;
  m_Exponent = exponent;
}

//------------------------------------------------------------------------------
bool PacketErrorRate::get(long& scalar, long& exponent) const {
  scalar   = m_Scalar;
  exponent = m_Exponent;

  return true;
}

//------------------------------------------------------------------------------
bool PacketErrorRate::encode(Ngap_PacketErrorRate_t& per) const {
  per.pERScalar   = m_Scalar;
  per.pERExponent = m_Exponent;

  return true;
}

//------------------------------------------------------------------------------
bool PacketErrorRate::decode(const Ngap_PacketErrorRate_t& per) {
  m_Scalar   = per.pERScalar;
  m_Exponent = per.pERExponent;

  return true;
}
}  // namespace oai::ngap
