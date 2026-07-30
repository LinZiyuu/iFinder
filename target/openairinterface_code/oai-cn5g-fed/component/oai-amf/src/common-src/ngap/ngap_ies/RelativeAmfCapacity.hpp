/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _RELATIVE_AMF_CAPACITY_H_
#define _RELATIVE_AMF_CAPACITY_H_

extern "C" {
#include "Ngap_RelativeAMFCapacity.h"
}

namespace oai::ngap {

class RelativeAmfCapacity {
 public:
  RelativeAmfCapacity();
  virtual ~RelativeAmfCapacity();

  void set(uint8_t amfCapacity);
  uint8_t get() const;

  bool encode(Ngap_RelativeAMFCapacity_t&) const;
  bool decode(const Ngap_RelativeAMFCapacity_t&);

 private:
  uint8_t m_AmfCapacity;
};
}  // namespace oai::ngap

#endif
