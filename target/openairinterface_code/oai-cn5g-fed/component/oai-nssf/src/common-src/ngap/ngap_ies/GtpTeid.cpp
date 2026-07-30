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

  for (int i = 0; i < gtpTeid.size; i++) {
    gtpTeid.buf[i] = (m_GtpTeid >> (gtpTeid.size - i - 1) * 8) & 0xff;
  }

  return true;
}

//------------------------------------------------------------------------------
bool GtpTeid::decode(const Ngap_GTP_TEID_t& gtpTeid) {
  if (!gtpTeid.buf) return false;

  m_GtpTeid = 0;
  for (int i = 0; i < gtpTeid.size; i++) {
    m_GtpTeid = m_GtpTeid << 8;
    m_GtpTeid |= gtpTeid.buf[i];
  }

  return true;
}

}  // namespace oai::ngap
