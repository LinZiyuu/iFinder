/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "RoutingId.hpp"
namespace oai::ngap {

//------------------------------------------------------------------------------
RoutingId::RoutingId() {}

//------------------------------------------------------------------------------
RoutingId::~RoutingId() {}

//------------------------------------------------------------------------------
void RoutingId::set(const OCTET_STRING_t& id) {
  m_RoutingId = id;
}

//------------------------------------------------------------------------------
void RoutingId::get(OCTET_STRING_t& id) const {
  id = m_RoutingId;
}

//------------------------------------------------------------------------------
void RoutingId::encode(Ngap_RoutingID_t& id) const {
  id = m_RoutingId;
}

//------------------------------------------------------------------------------
void RoutingId::decode(const Ngap_RoutingID_t& id) {
  m_RoutingId = id;
}
}  // namespace oai::ngap
