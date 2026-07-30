/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "SecurityKey.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
SecurityKey::SecurityKey() {
  m_Buffer = nullptr;
  m_Size   = 0;
}

//------------------------------------------------------------------------------
SecurityKey::~SecurityKey() {}

//------------------------------------------------------------------------------
bool SecurityKey::encode(Ngap_SecurityKey_t& security_key) const {
  security_key.bits_unused = 0;
  security_key.size        = 32;
  security_key.buf         = (uint8_t*) calloc(1, 32);
  if (!security_key.buf) return false;
  memcpy(security_key.buf, m_Buffer, 32);
  return true;
}

//------------------------------------------------------------------------------
bool SecurityKey::decode(const Ngap_SecurityKey_t& security_key) {
  m_Buffer = (uint8_t*) calloc(1, security_key.size);
  memcpy(m_Buffer, security_key.buf, security_key.size);
  m_Size = security_key.size;
  return true;
}

//------------------------------------------------------------------------------
bool SecurityKey::get(uint8_t*& buffer, size_t& size) const {
  if (!m_Buffer) return false;
  if (!buffer) buffer = (uint8_t*) calloc(1, m_Size);
  memcpy(buffer, m_Buffer, m_Size);
  size = m_Size;
  return true;
}

//------------------------------------------------------------------------------
bool SecurityKey::get(uint8_t*& buffer) const {
  if (!m_Buffer) return false;
  if (!buffer) buffer = (uint8_t*) calloc(1, m_Size);
  memcpy(buffer, m_Buffer, m_Size);
  return true;
}

//------------------------------------------------------------------------------
void SecurityKey::set(uint8_t* buffer, const size_t& size) {
  if (!m_Buffer) m_Buffer = (uint8_t*) calloc(1, size);
  memcpy(m_Buffer, buffer, size);
  m_Size = size;
}
}  // namespace oai::ngap
