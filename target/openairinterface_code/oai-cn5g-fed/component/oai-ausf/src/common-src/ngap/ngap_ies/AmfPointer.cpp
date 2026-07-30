/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "AmfPointer.hpp"

#include "utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
AmfPointer::AmfPointer() {
  m_Pointer = 0;
}

//------------------------------------------------------------------------------
AmfPointer::~AmfPointer() {}

//------------------------------------------------------------------------------
bool AmfPointer::set(const std::string& pointer) {
  uint8_t tmp = oai::utils::utils::fromString<int>(pointer);
  if (tmp > kAmfPointerMaxValue) return false;
  m_Pointer = tmp;
  return true;
}

//------------------------------------------------------------------------------
bool AmfPointer::set(const uint8_t& pointer) {
  if (pointer > kAmfPointerMaxValue) return false;
  m_Pointer = pointer;
  return true;
}

//------------------------------------------------------------------------------
void AmfPointer::get(std::string& pointer) const {
  pointer = std::to_string(m_Pointer);
}

//------------------------------------------------------------------------------
void AmfPointer::get(uint8_t& pointer) const {
  pointer = m_Pointer;
}

//------------------------------------------------------------------------------
bool AmfPointer::encode(Ngap_AMFPointer_t& amf_pointer) const {
  amf_pointer.size = 1;
  uint8_t* buffer  = (uint8_t*) calloc(1, sizeof(uint8_t));
  if (!buffer) return false;
  *buffer                 = ((m_Pointer & 0x3f) << 2);
  amf_pointer.buf         = buffer;
  amf_pointer.bits_unused = 2;

  return true;
}

//------------------------------------------------------------------------------
bool AmfPointer::decode(const Ngap_AMFPointer_t& amf_pointer) {
  if (!amf_pointer.buf) return false;
  m_Pointer = (amf_pointer.buf[0] & 0xfc) >> 2;  // 1111 1100

  return true;
}
}  // namespace oai::ngap
