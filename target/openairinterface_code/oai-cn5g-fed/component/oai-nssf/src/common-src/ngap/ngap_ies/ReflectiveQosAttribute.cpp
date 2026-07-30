/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "ReflectiveQosAttribute.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
ReflectiveQosAttribute::ReflectiveQosAttribute() {
  m_Attribute = 0;
}

//------------------------------------------------------------------------------
ReflectiveQosAttribute::ReflectiveQosAttribute(
    e_Ngap_ReflectiveQosAttribute value) {
  m_Attribute = value;
}
//------------------------------------------------------------------------------
ReflectiveQosAttribute::~ReflectiveQosAttribute() {}

//------------------------------------------------------------------------------
void ReflectiveQosAttribute::set(e_Ngap_ReflectiveQosAttribute value) {
  m_Attribute = value;
}

//------------------------------------------------------------------------------
bool ReflectiveQosAttribute::get(e_Ngap_ReflectiveQosAttribute& value) const {
  if (m_Attribute == 0)
    value = (e_Ngap_ReflectiveQosAttribute) m_Attribute;
  else
    return false;

  return true;
}

//------------------------------------------------------------------------------
bool ReflectiveQosAttribute::encode(
    Ngap_ReflectiveQosAttribute_t& value) const {
  value = m_Attribute;

  return true;
}

//------------------------------------------------------------------------------
bool ReflectiveQosAttribute::decode(
    const Ngap_ReflectiveQosAttribute_t& value) {
  m_Attribute = value;

  return true;
}
}  // namespace oai::ngap
