/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "AmfUeNgapId.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
AmfUeNgapId::AmfUeNgapId() {
  m_AmfUeNgapId = 0;
}

//------------------------------------------------------------------------------
AmfUeNgapId::~AmfUeNgapId() {}

//------------------------------------------------------------------------------
bool AmfUeNgapId::set(const uint64_t& id) {
  if (id > AMF_UE_NGAP_ID_MAX_VALUE) return false;
  m_AmfUeNgapId = id;
  return true;
}

//------------------------------------------------------------------------------
uint64_t AmfUeNgapId::get() const {
  return m_AmfUeNgapId;
}

//------------------------------------------------------------------------------
bool AmfUeNgapId::encode(Ngap_AMF_UE_NGAP_ID_t& amf_ue_ngap_id) const {
  amf_ue_ngap_id.size = 5;  // 40 bits
  amf_ue_ngap_id.buf  = (uint8_t*) calloc(1, amf_ue_ngap_id.size);
  if (!amf_ue_ngap_id.buf) return false;

  for (int i = 0; i < amf_ue_ngap_id.size; i++) {
    amf_ue_ngap_id.buf[i] = (m_AmfUeNgapId & (0xff00000000 >> i * 8)) >>
                            ((amf_ue_ngap_id.size - i - 1) * 8);
  }

  return true;
}

//------------------------------------------------------------------------------
bool AmfUeNgapId::decode(const Ngap_AMF_UE_NGAP_ID_t& amf_ue_ngap_id) {
  if (!amf_ue_ngap_id.buf or (amf_ue_ngap_id.size > 5))
    return false;  // 5 bytes = 40 bits

  m_AmfUeNgapId = 0;
  for (int i = 0; i < amf_ue_ngap_id.size; i++) {
    m_AmfUeNgapId = m_AmfUeNgapId << 8;
    m_AmfUeNgapId |= amf_ue_ngap_id.buf[i];
  }

  return true;
}
}  // namespace oai::ngap
