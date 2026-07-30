/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "Tac.hpp"

#include "logger_base.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
TAC::TAC() {
  m_Tac = 0;
}

//------------------------------------------------------------------------------
TAC::~TAC() {}

//------------------------------------------------------------------------------
void TAC::set(const uint32_t& tac) {
  m_Tac = tac;
}

//------------------------------------------------------------------------------
uint32_t TAC::get() const {
  return m_Tac;
}

//------------------------------------------------------------------------------
bool TAC::encode(Ngap_TAC_t& tac) const {
  tac.size   = 3;  // OCTET_STRING(SIZE(3))
  tac.buf    = (uint8_t*) calloc(3, sizeof(uint8_t));
  tac.buf[2] = m_Tac & 0x0000ff;
  tac.buf[1] = (m_Tac & 0x00ff00) >> 8;
  tac.buf[0] = (m_Tac & 0xff0000) >> 16;

  return true;
}

//------------------------------------------------------------------------------
bool TAC::decode(const Ngap_TAC_t& tac) {
  if (!tac.buf) return false;
  m_Tac = 0;
  for (int i = 0; i < tac.size; i++) {
    m_Tac |= tac.buf[i] << ((tac.size - 1 - i) * 8);
  }
  oai::logger::logger_common::ngap().debug("Received TAC 0x%x", m_Tac);
  return true;
}

}  // namespace oai::ngap
