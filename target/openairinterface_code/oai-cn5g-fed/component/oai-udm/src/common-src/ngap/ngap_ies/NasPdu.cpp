/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "NasPdu.hpp"

#include "ngap_utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
NasPdu::NasPdu() {
  m_Pdu = nullptr;
}

//------------------------------------------------------------------------------
NasPdu::~NasPdu() {}

//------------------------------------------------------------------------------
bool NasPdu::encode(Ngap_NAS_PDU_t& nasPdu) const {
  return ngap_utils::bstring_2_octet_string(m_Pdu, nasPdu);
}

//------------------------------------------------------------------------------
bool NasPdu::decode(const Ngap_NAS_PDU_t& nasPdu) {
  if (!nasPdu.buf) return false;
  return ngap_utils::octet_string_2_bstring(nasPdu, m_Pdu);
}
/*

//------------------------------------------------------------------------------
bool NasPdu::get(uint8_t*& buffer, size_t& size) const {
  if (!pdu_.buf) return false;
  if (pdu_.size < 0) return false;
  memcpy(buffer, pdu_.buf, pdu_.size);
  size = pdu_.size;
  return true;
}
*/
//------------------------------------------------------------------------------
void NasPdu::set(uint8_t* buffer, size_t size) {
  if (!buffer) return;
  m_Pdu = blk2bstr(buffer, size);
  return;
}

//------------------------------------------------------------------------------
bool NasPdu::get(OCTET_STRING_t& pdu) const {
  ngap_utils::bstring_2_octet_string(m_Pdu, pdu);
  return true;
}

//------------------------------------------------------------------------------
bool NasPdu::set(const OCTET_STRING_t& pdu) {
  ngap_utils::octet_string_2_bstring(pdu, m_Pdu);
  return true;
}

//------------------------------------------------------------------------------
bool NasPdu::get(NasPdu& nasPdu) const {
  return nasPdu.set(m_Pdu);
}

//------------------------------------------------------------------------------
bool NasPdu::set(const NasPdu& nasPdu) {
  bstring pdu = {};
  if (!nasPdu.get(pdu)) return false;
  return set(pdu);
}

//------------------------------------------------------------------------------
bool NasPdu::get(bstring& pdu) const {
  pdu = bstrcpy(m_Pdu);
  return true;
}

//------------------------------------------------------------------------------
bool NasPdu::set(const bstring& pdu) {
  m_Pdu = bstrcpy(pdu);
  return true;
}
}  // namespace oai::ngap
