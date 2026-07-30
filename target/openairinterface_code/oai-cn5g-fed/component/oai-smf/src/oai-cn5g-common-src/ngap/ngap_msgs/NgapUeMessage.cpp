/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "NgapUeMessage.hpp"

#include "logger_base.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
NgapUeMessage::NgapUeMessage() : NgapMessage() {}

//------------------------------------------------------------------------------
NgapUeMessage::~NgapUeMessage() {}

//------------------------------------------------------------------------------
uint64_t NgapUeMessage::getAmfUeNgapId() const {
  return m_AmfUeNgapId.get();
}

//------------------------------------------------------------------------------
uint32_t NgapUeMessage::getRanUeNgapId() const {
  return m_RanUeNgapId.get();
}

}  // namespace oai::ngap
