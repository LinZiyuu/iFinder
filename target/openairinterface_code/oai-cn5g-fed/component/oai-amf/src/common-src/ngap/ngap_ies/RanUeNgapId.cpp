/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "RanUeNgapId.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
RanUeNgapId::RanUeNgapId() {
  m_Id = 0;
}

//------------------------------------------------------------------------------
RanUeNgapId::RanUeNgapId(uint32_t id) : m_Id(id) {}

//------------------------------------------------------------------------------
RanUeNgapId::~RanUeNgapId() {}

//------------------------------------------------------------------------------
void RanUeNgapId::set(const uint32_t& id) {
  m_Id = id;
}

//------------------------------------------------------------------------------
uint32_t RanUeNgapId::get() const {
  return m_Id;
}

//------------------------------------------------------------------------------
bool RanUeNgapId::encode(Ngap_RAN_UE_NGAP_ID_t& ranUeNgapId) const {
  ranUeNgapId = m_Id;
  return true;
}

//------------------------------------------------------------------------------
bool RanUeNgapId::decode(const Ngap_RAN_UE_NGAP_ID_t& ranUeNgapId) {
  m_Id = ranUeNgapId;
  return true;
}
}  // namespace oai::ngap
