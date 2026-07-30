/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "AmfName.hpp"

#include "ngap_utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
AmfName::AmfName() {}

//------------------------------------------------------------------------------
AmfName::~AmfName() {}

//------------------------------------------------------------------------------
bool AmfName::set(const std::string& amf_name) {
  if (amf_name.size() > AMF_NAME_SIZE_MAX) return false;
  m_AmfName = amf_name;
  return true;
}

//------------------------------------------------------------------------------
void AmfName::get(std::string& amf_name) const {
  amf_name = m_AmfName;
}

//------------------------------------------------------------------------------
bool AmfName::encode(Ngap_AMFName_t& amf_name) const {
  ngap_utils::string_2_octet_string(m_AmfName, amf_name);
  return true;
}

//------------------------------------------------------------------------------
bool AmfName::decode(const Ngap_AMFName_t& amf_name) {
  if (!amf_name.buf) return false;
  ngap_utils::octet_string_2_string(amf_name, m_AmfName);
  return true;
}

}  // namespace oai::ngap
