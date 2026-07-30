/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "GtpTeid.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
GtpTeid::GtpTeid() {
  m_GtpTeid = 0;
}

//------------------------------------------------------------------------------
GtpTeid::~GtpTeid() {}

//------------------------------------------------------------------------------
void GtpTeid::set(const uint32_t gtpTeid) {
  m_GtpTeid = gtpTeid;
}

//------------------------------------------------------------------------------
bool GtpTeid::get(uint32_t& gtpTeid) const {
  gtpTeid = m_GtpTeid;

  return true;
}

//------------------------------------------------------------------------------
bool GtpTeid::encode(Ngap_GTP_TEID_t& gtpTeid) const {
  gtpTeid.size = sizeof(uint32_t);
  gtpTeid.buf  = (uint8_t*) calloc(1, sizeof(uint32_t));
  if (!gtpTeid.buf) return false;

  gtpTeid.buf[3] = m_GtpTeid & 0x000000ff;
  gtpTeid.buf[2] = (m_GtpTeid & 0x0000ff00) >> 8;
  gtpTeid.buf[1] = (m_GtpTeid & 0x00ff0000) >> 16;
  gtpTeid.buf[0] = (m_GtpTeid & 0xff000000) >> 24;

  return true;
}

//------------------------------------------------------------------------------
bool GtpTeid::decode(const Ngap_GTP_TEID_t& gtpTeid) {
  if (!gtpTeid.buf) return false;

  m_GtpTeid = 0;
  m_GtpTeid = gtpTeid.buf[0] << 24;
  m_GtpTeid |= gtpTeid.buf[1] << 16;
  m_GtpTeid |= gtpTeid.buf[2] << 8;
  m_GtpTeid |= gtpTeid.buf[3];

  return true;
}

}  // namespace oai::ngap
