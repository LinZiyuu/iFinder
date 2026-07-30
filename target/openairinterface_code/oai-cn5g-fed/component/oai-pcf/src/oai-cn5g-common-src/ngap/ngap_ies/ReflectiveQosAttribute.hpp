/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _REFLECTIVE_QOS_ATTRIBUTE_H_
#define _REFLECTIVE_QOS_ATTRIBUTE_H_

extern "C" {
#include "Ngap_ReflectiveQosAttribute.h"
}

namespace oai::ngap {

class ReflectiveQosAttribute {
 public:
  ReflectiveQosAttribute();
  ReflectiveQosAttribute(e_Ngap_ReflectiveQosAttribute value);
  virtual ~ReflectiveQosAttribute();

  void set(e_Ngap_ReflectiveQosAttribute value);
  bool get(e_Ngap_ReflectiveQosAttribute& value) const;

  bool encode(Ngap_ReflectiveQosAttribute_t&) const;
  bool decode(const Ngap_ReflectiveQosAttribute_t&);

 private:
  long m_Attribute;
};

}  // namespace oai::ngap

#endif
