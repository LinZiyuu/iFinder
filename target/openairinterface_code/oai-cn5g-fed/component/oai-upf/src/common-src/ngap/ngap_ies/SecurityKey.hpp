/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _SECURITY_KEY_H_
#define _SECURITY_KEY_H_

extern "C" {
#include "Ngap_SecurityKey.h"
}

namespace oai::ngap {

class SecurityKey {
 public:
  SecurityKey();
  virtual ~SecurityKey();

  void set(uint8_t* buffer, const size_t& size = 256);
  bool get(uint8_t*& buffer, size_t& size) const;
  bool get(uint8_t*& buffer) const;

  bool encode(Ngap_SecurityKey_t&) const;
  bool decode(const Ngap_SecurityKey_t&);

 private:
  uint8_t* m_Buffer;
  size_t m_Size;
};

}  // namespace oai::ngap

#endif
