/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "MaximumDataBurstVolume.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
MaximumDataBurstVolume::MaximumDataBurstVolume() {
  m_MaximumDataBurstVolume = 0;
}

//------------------------------------------------------------------------------
MaximumDataBurstVolume::~MaximumDataBurstVolume() {}

//------------------------------------------------------------------------------
void MaximumDataBurstVolume::set(const long& value) {
  m_MaximumDataBurstVolume = value;
}

//------------------------------------------------------------------------------
void MaximumDataBurstVolume::get(long& value) const {
  value = m_MaximumDataBurstVolume;
}

//------------------------------------------------------------------------------
bool MaximumDataBurstVolume::encode(
    Ngap_MaximumDataBurstVolume_t& value) const {
  value = m_MaximumDataBurstVolume;

  return true;
}

//------------------------------------------------------------------------------
bool MaximumDataBurstVolume::decode(
    const Ngap_MaximumDataBurstVolume_t& value) {
  m_MaximumDataBurstVolume = value;

  return true;
}
}  // namespace oai::ngap
