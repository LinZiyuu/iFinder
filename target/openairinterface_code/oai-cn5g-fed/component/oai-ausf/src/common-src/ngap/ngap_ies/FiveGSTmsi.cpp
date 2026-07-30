/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "FiveGSTmsi.hpp"

#include <arpa/inet.h>

#include "conversions.hpp"

using namespace oai::ngap;

//------------------------------------------------------------------------------
FiveGSTmsi::FiveGSTmsi() {}

//------------------------------------------------------------------------------
FiveGSTmsi::~FiveGSTmsi() {}

//------------------------------------------------------------------------------
void FiveGSTmsi::getTmsi(std::string& tmsi) const {
  tmsi = m_5gSTmsi;
}

//------------------------------------------------------------------------------
void FiveGSTmsi::get(
    std::string& set_id, std::string& pointer, std::string& tmsi) const {
  m_AmfSetId.get(set_id);
  m_AmfPointer.get(pointer);
  tmsi = m_TmsiValue;
}

//------------------------------------------------------------------------------
bool FiveGSTmsi::set(
    const std::string& set_id, const std::string& pointer,
    const std::string& tmsi) {
  if (!m_AmfSetId.set(set_id)) return false;
  if (!m_AmfPointer.set(pointer)) return false;
  m_TmsiValue = tmsi;
  return true;
}

//------------------------------------------------------------------------------
bool FiveGSTmsi::encode(Ngap_FiveG_S_TMSI_t& pdu) const {
  m_AmfSetId.encode(pdu.aMFSetID);
  m_AmfPointer.encode(pdu.aMFPointer);

  uint32_t tmsi       = (uint32_t) std::stol(m_TmsiValue);
  uint8_t* buf        = (uint8_t*) malloc(sizeof(uint32_t));
  *(uint32_t*) buf    = htonl(tmsi);
  pdu.fiveG_TMSI.buf  = buf;
  pdu.fiveG_TMSI.size = sizeof(uint32_t);

  return true;
}

//------------------------------------------------------------------------------
bool FiveGSTmsi::decode(const Ngap_FiveG_S_TMSI_t& pdu) {
  m_AmfSetId.decode(pdu.aMFSetID);
  m_AmfPointer.decode(pdu.aMFPointer);

  uint32_t tmsi = ntohl(*(uint32_t*) pdu.fiveG_TMSI.buf);
  int size      = pdu.fiveG_TMSI.size;

  // AMF Set ID: 10 bits, AMF pointer ID: 6 bits
  uint16_t amfSetIdValue = 0;
  m_AmfSetId.get(amfSetIdValue);
  uint8_t amfPointerValue = 0;
  m_AmfPointer.get(amfPointerValue);
  uint16_t firstPartTmsi =
      0xffff & (((amfSetIdValue & 0x03ff) << 6) | (amfPointerValue & 0x3f));
  std::string firstPartTmsiStr = {};
  oai::utils::conv::int_to_string_hex(firstPartTmsi, firstPartTmsiStr, 4);

  m_TmsiValue = oai::utils::conv::tmsi_to_string(tmsi);
  m_5gSTmsi   = firstPartTmsiStr + m_TmsiValue;
  return true;
}
