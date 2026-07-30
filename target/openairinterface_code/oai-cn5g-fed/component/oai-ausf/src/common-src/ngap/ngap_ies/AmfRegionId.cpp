/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "AmfRegionId.hpp"

#include "utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
AmfRegionId::AmfRegionId() {
  m_RegionId = 0;
}

//------------------------------------------------------------------------------
AmfRegionId::~AmfRegionId() {}

//------------------------------------------------------------------------------
void AmfRegionId::set(const std::string& id) {
  m_RegionId = oai::utils::utils::fromString<int>(id);
}

//------------------------------------------------------------------------------
void AmfRegionId::set(const uint8_t& id) {
  m_RegionId = id;
}

//------------------------------------------------------------------------------
void AmfRegionId::get(std::string& id) const {
  id = std::to_string(m_RegionId);
}

//------------------------------------------------------------------------------
void AmfRegionId::get(uint8_t& id) const {
  id = m_RegionId;
}

//------------------------------------------------------------------------------
bool AmfRegionId::encode(Ngap_AMFRegionID_t& id) const {
  id.size         = 1;
  uint8_t* buffer = (uint8_t*) calloc(1, sizeof(uint8_t));
  if (!buffer) return false;
  *buffer        = m_RegionId;
  id.buf         = buffer;
  id.bits_unused = 0;

  return true;
}

//------------------------------------------------------------------------------
bool AmfRegionId::decode(const Ngap_AMFRegionID_t& id) {
  if (!id.buf) return false;
  m_RegionId = *id.buf;

  return true;
}
}  // namespace oai::ngap
