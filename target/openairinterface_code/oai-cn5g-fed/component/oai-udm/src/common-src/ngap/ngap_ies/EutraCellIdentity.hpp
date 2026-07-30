/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _EUTRA_CELL_IDENTITY_H_
#define _EUTRA_CELL_IDENTITY_H_
#include <cstdint>

constexpr uint32_t kEUTRACellIdentityMaxValue = 268435455;  // 2^28-1

extern "C" {
#include "Ngap_EUTRACellIdentity.h"
}

namespace oai::ngap {

class EutraCellIdentity {
 public:
  EutraCellIdentity();
  virtual ~EutraCellIdentity();

  uint32_t get() const;
  bool set(const uint32_t& eutraCellIdentity);

  bool encode(Ngap_EUTRACellIdentity_t& eutraCellIdentity) const;
  bool decode(const Ngap_EUTRACellIdentity_t& eutraCellIdentity);

 private:
  uint32_t m_EutraCellIdentity;
};
}  // namespace oai::ngap

#endif
