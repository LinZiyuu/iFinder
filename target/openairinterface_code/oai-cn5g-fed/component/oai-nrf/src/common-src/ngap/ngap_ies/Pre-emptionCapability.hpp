/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PRE_EMPTION_CAPABILITY_H_
#define _PRE_EMPTION_CAPABILITY_H_

extern "C" {
#include "Ngap_Pre-emptionCapability.h"
}

namespace oai::ngap {

class Pre_emptionCapability {
 public:
  Pre_emptionCapability();
  virtual ~Pre_emptionCapability();

  void set(e_Ngap_Pre_emptionCapability value);
  bool get(e_Ngap_Pre_emptionCapability& value) const;

  bool encode(Ngap_Pre_emptionCapability_t&) const;
  bool decode(const Ngap_Pre_emptionCapability_t&);

 private:
  long m_Pre_emptionCapability;
};

}  // namespace oai::ngap

#endif
