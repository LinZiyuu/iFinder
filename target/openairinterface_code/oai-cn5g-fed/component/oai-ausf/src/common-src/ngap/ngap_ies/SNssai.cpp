/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "SNssai.hpp"

#include "3gpp_23.003.h"
#include "conversions.hpp"
#include "ngap_utils.hpp"
#include "utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
SNssai::SNssai() {
  //  sdIsSet = false;
  m_Sst = 0;
  //  sd      = SD_NO_VALUE;
  m_Sd = std::nullopt;
}

//------------------------------------------------------------------------------
SNssai::~SNssai() {}

//------------------------------------------------------------------------------
bool SNssai::encodeSd(Ngap_SD_t& m_sd) const {
  if (!m_Sd.has_value()) {
    return false;
  }
  m_sd.size = 3;
  m_sd.buf  = (uint8_t*) calloc(3, sizeof(uint8_t));
  if (!m_sd.buf) return false;
  m_sd.buf[0] = (m_Sd.value() & 0x00ff0000) >> 16;
  m_sd.buf[1] = (m_Sd.value() & 0x0000ff00) >> 8;
  m_sd.buf[2] = (m_Sd.value() & 0x000000ff) >> 0;
  return true;
}

//------------------------------------------------------------------------------
bool SNssai::decodeSd(const Ngap_SD_t& m_sd) {
  if (!m_sd.buf) return false;

  uint32_t value = SD_NO_VALUE;
  if (m_sd.size == 3) {
    value = ((m_sd.buf[0] << 16) + (m_sd.buf[1] << 8) + m_sd.buf[2]);
    m_Sd  = std::optional<uint32_t>(value);
    return true;
  } else if (m_sd.size == 4) {
    value = ((m_sd.buf[1] << 16) + (m_sd.buf[2] << 8) + m_sd.buf[3]);
    m_Sd  = std::optional<uint32_t>(value);
    return true;
  }

  return false;
}

//------------------------------------------------------------------------------
void SNssai::setSst(const std::string& sst) {
  oai::utils::conv::string_to_int8(sst, m_Sst);
}

//------------------------------------------------------------------------------
void SNssai::setSst(const uint8_t& sst) {
  m_Sst = sst;
}
//------------------------------------------------------------------------------
void SNssai::getSst(std::string& sst) const {
  sst = std::to_string(m_Sst);
}

//------------------------------------------------------------------------------
std::string SNssai::getSstStr() const {
  return std::to_string(m_Sst);
}

//------------------------------------------------------------------------------
void SNssai::getSst(uint8_t& sst) const {
  sst = m_Sst;
}

//------------------------------------------------------------------------------
uint8_t SNssai::getSst() const {
  return m_Sst;
}

//------------------------------------------------------------------------------
void SNssai::setSd(const std::string& sd_str) {
  snssai_t snssai;
  snssai.sd = sd_str;
  m_Sd      = std::optional<uint32_t>(snssai.get_sd_int());
}

//------------------------------------------------------------------------------
void SNssai::setSd(const uint32_t& sd) {
  m_Sd = std::optional<uint32_t>(sd);
}

//------------------------------------------------------------------------------
bool SNssai::getSd(std::string& sd) const {
  if (m_Sd.has_value()) {
    ngap_utils::sd_int_to_string_hex(m_Sd.value(), sd);
    return true;
  }
  ngap_utils::sd_int_to_string_hex(SD_NO_VALUE, sd);
  return false;
}

//------------------------------------------------------------------------------
bool SNssai::getSd(uint32_t& sd) const {
  if (m_Sd.has_value()) {
    sd = m_Sd.value();
    return true;
  }
  sd = SD_NO_VALUE;
  return false;
}

//------------------------------------------------------------------------------
std::string SNssai::getSd() const {
  std::string sd;
  getSd(sd);
  return sd;
}

//------------------------------------------------------------------------------
uint32_t SNssai::getSdInt() const {
  if (m_Sd.has_value()) {
    return m_Sd.value();
  }
  return SD_NO_VALUE;
}
//------------------------------------------------------------------------------
bool SNssai::encode(Ngap_S_NSSAI_t& s_NSSAI) const {
  ngap_utils::int8_2_octet_string(m_Sst, s_NSSAI.sST);
  if (m_Sd.has_value() && (m_Sd.value() != SD_NO_VALUE)) {
    s_NSSAI.sD = (Ngap_SD_t*) calloc(1, sizeof(Ngap_SD_t));
    if (!s_NSSAI.sD) return false;
    if (!encodeSd(*s_NSSAI.sD)) {
      return false;
    }
  }
  return true;
}

//------------------------------------------------------------------------------
bool SNssai::decode(const Ngap_S_NSSAI_t& s_NSSAI) {
  if (!ngap_utils::octet_string_2_int8(s_NSSAI.sST, m_Sst)) return false;
  if (s_NSSAI.sD) {
    if (!decodeSd(*s_NSSAI.sD)) return false;
  }
  return true;
}

}  // namespace oai::ngap
