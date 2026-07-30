/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _AMF_POINTER_H_
#define _AMF_POINTER_H_

#include <string>

constexpr uint8_t kAmfPointerMaxValue = 63;  // 6 bits

extern "C" {
#include "Ngap_AMFPointer.h"
}

namespace oai::ngap {

class AmfPointer {
 public:
  AmfPointer();
  virtual ~AmfPointer();

  bool set(const std::string&);
  void get(std::string&) const;

  bool set(const uint8_t&);
  void get(uint8_t&) const;

  bool encode(Ngap_AMFPointer_t&) const;
  bool decode(const Ngap_AMFPointer_t&);

 private:
  uint8_t m_Pointer;
};

}  // namespace oai::ngap

#endif
