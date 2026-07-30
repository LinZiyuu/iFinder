/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "EutraCellIdentity.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
EutraCellIdentity::EutraCellIdentity() {
  m_EutraCellIdentity = 0;
}

//------------------------------------------------------------------------------
EutraCellIdentity::~EutraCellIdentity() {}

//------------------------------------------------------------------------------
bool EutraCellIdentity::set(const uint32_t& id) {
  if (id > kEUTRACellIdentityMaxValue) return false;
  m_EutraCellIdentity = id;
  return true;
}

//------------------------------------------------------------------------------
uint32_t EutraCellIdentity::get() const {
  return m_EutraCellIdentity;
}

//------------------------------------------------------------------------------
bool EutraCellIdentity::encode(
    Ngap_EUTRACellIdentity_t& eutraCellIdentity) const {
  eutraCellIdentity.bits_unused = 4;  // 28 = 4*8 - 4 bits
  eutraCellIdentity.size        = 4;
  eutraCellIdentity.buf         = (uint8_t*) calloc(1, sizeof(uint32_t));
  if (!eutraCellIdentity.buf) return false;
  eutraCellIdentity.buf[3] = m_EutraCellIdentity & 0x000000ff;
  eutraCellIdentity.buf[2] = (m_EutraCellIdentity & 0x0000ff00) >> 8;
  eutraCellIdentity.buf[1] = (m_EutraCellIdentity & 0x00ff0000) >> 16;
  eutraCellIdentity.buf[0] = (m_EutraCellIdentity & 0xff000000) >> 24;

  return true;
}

//------------------------------------------------------------------------------
bool EutraCellIdentity::decode(
    const Ngap_EUTRACellIdentity_t& eutraCellIdentity) {
  if (!eutraCellIdentity.buf) return false;

  m_EutraCellIdentity = eutraCellIdentity.buf[0] << 24;
  m_EutraCellIdentity |= eutraCellIdentity.buf[1] << 16;
  m_EutraCellIdentity |= eutraCellIdentity.buf[2] << 8;
  m_EutraCellIdentity |= eutraCellIdentity.buf[3];

  return true;
}
}  // namespace oai::ngap
