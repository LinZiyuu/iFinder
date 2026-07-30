/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "RanPagingPriority.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
RanPagingPriority::RanPagingPriority() {
  m_RanPagingPriority = 0;
}

//------------------------------------------------------------------------------
RanPagingPriority::~RanPagingPriority() {}

//------------------------------------------------------------------------------
bool RanPagingPriority::set(const uint32_t& ranPagingPriority) {
  if (ranPagingPriority > kRANPagingPriorityMaxValue) return false;
  m_RanPagingPriority = ranPagingPriority;
  return true;
}

//------------------------------------------------------------------------------
uint32_t RanPagingPriority::get() const {
  return m_RanPagingPriority;
}

//------------------------------------------------------------------------------
bool RanPagingPriority::encode(
    Ngap_RANPagingPriority_t& ranPagingPriority) const {
  ranPagingPriority = m_RanPagingPriority;
  return true;
}

//------------------------------------------------------------------------------
bool RanPagingPriority::decode(
    const Ngap_RANPagingPriority_t& ranPagingPriority) {
  if (ranPagingPriority > kRANPagingPriorityMaxValue) return false;
  m_RanPagingPriority = ranPagingPriority;
  return true;
}
}  // namespace oai::ngap
