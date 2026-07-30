/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "NrCellIdentity.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
NrCellIdentity::NrCellIdentity() {
  m_NrCellIdentity = 0;
}

//------------------------------------------------------------------------------
NrCellIdentity::~NrCellIdentity() {}

//------------------------------------------------------------------------------
void NrCellIdentity::set(const unsigned long& nrCellIdentity) {
  m_NrCellIdentity = nrCellIdentity;
}

//------------------------------------------------------------------------------
bool NrCellIdentity::encode(Ngap_NRCellIdentity_t& nrCellIdentity) const {
  nrCellIdentity.bits_unused = 4;
  nrCellIdentity.size        = 5;
  nrCellIdentity.buf = (uint8_t*) calloc(1, sizeof(uint32_t) + sizeof(uint8_t));
  if (!nrCellIdentity.buf) return false;
  nrCellIdentity.buf[4] = m_NrCellIdentity & 0x00000000ff;
  nrCellIdentity.buf[3] = (m_NrCellIdentity & 0x000000ff00) >> 8;
  nrCellIdentity.buf[2] = (m_NrCellIdentity & 0x0000ff0000) >> 16;
  nrCellIdentity.buf[1] = (m_NrCellIdentity & 0x00ff000000) >> 24;
  nrCellIdentity.buf[0] = (m_NrCellIdentity & 0xff00000000) >> 32;

  return true;
}

//------------------------------------------------------------------------------
bool NrCellIdentity::decode(const Ngap_NRCellIdentity_t& nrCellIdentity) {
  if (!nrCellIdentity.buf) return false;

  m_NrCellIdentity = nrCellIdentity.buf[0];
  m_NrCellIdentity = m_NrCellIdentity << 32;
  m_NrCellIdentity |= nrCellIdentity.buf[1] << 24;
  m_NrCellIdentity |= nrCellIdentity.buf[2] << 16;
  m_NrCellIdentity |= nrCellIdentity.buf[3] << 8;
  m_NrCellIdentity |= nrCellIdentity.buf[4];

  return true;
}

//------------------------------------------------------------------------------
unsigned long NrCellIdentity::get() const {
  return m_NrCellIdentity;
}
}  // namespace oai::ngap
