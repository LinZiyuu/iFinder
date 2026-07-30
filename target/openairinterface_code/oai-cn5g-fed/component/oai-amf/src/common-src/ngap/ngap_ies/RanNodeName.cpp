/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "RanNodeName.hpp"

#include "ngap_utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
RanNodeName::RanNodeName() {
  m_RanNodeName = {};
}

//------------------------------------------------------------------------------
RanNodeName::~RanNodeName() {}

//------------------------------------------------------------------------------
bool RanNodeName::set(const std::string& value) {
  if (value.size() > RAN_NODE_NAME_SIZE_MAX) return false;
  m_RanNodeName = value;
  return true;
}

//------------------------------------------------------------------------------
void RanNodeName::get(std::string& value) const {
  value = m_RanNodeName;
}

//------------------------------------------------------------------------------
bool RanNodeName::encode(Ngap_RANNodeName_t& ranNodeName) const {
  ngap_utils::string_2_octet_string(m_RanNodeName, ranNodeName);
  return true;
}

//------------------------------------------------------------------------------
bool RanNodeName::decode(const Ngap_RANNodeName_t& ranNodeName) {
  if (!ranNodeName.buf) return false;
  ngap_utils::octet_string_2_string(ranNodeName, m_RanNodeName);
  return true;
}

}  // namespace oai::ngap
