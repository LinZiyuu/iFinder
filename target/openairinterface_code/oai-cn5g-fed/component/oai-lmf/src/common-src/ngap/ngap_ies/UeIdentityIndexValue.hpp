/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _UE_IDENTITY_INDEX_VALUE_H_
#define _UE_IDENTITY_INDEX_VALUE_H_

extern "C" {
#include "Ngap_UEIdentityIndexValue.h"
}

namespace oai::ngap {

class UeIdentityIndexValue {
 public:
  UeIdentityIndexValue();
  virtual ~UeIdentityIndexValue();

  void set(const uint16_t& index);
  bool get(uint16_t& index) const;

  bool encode(Ngap_UEIdentityIndexValue_t& index) const;
  bool decode(const Ngap_UEIdentityIndexValue_t& index);

 private:
  uint16_t m_Index;
  Ngap_UEIdentityIndexValue_PR m_Present;
};

}  // namespace oai::ngap

#endif
