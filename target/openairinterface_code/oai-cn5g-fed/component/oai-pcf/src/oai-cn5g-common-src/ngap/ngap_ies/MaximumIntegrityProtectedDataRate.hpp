/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _MAXIMUM_INTEGRITY_PROTECTED_DATA_RATE_H_
#define _MAXIMUM_INTEGRITY_PROTECTED_DATA_RATE_H_

extern "C" {
#include "Ngap_MaximumIntegrityProtectedDataRate.h"
}

namespace oai::ngap {

class MaximumIntegrityProtectedDataRate {
 public:
  MaximumIntegrityProtectedDataRate();
  MaximumIntegrityProtectedDataRate(
      const e_Ngap_MaximumIntegrityProtectedDataRate& value);
  virtual ~MaximumIntegrityProtectedDataRate();

  void set(const e_Ngap_MaximumIntegrityProtectedDataRate& value);
  bool get(long& value) const;

  bool encode(Ngap_MaximumIntegrityProtectedDataRate_t&) const;
  bool decode(const Ngap_MaximumIntegrityProtectedDataRate_t&);

 private:
  long m_MaximumIntegrityProtectedDataRate;
};

}  // namespace oai::ngap

#endif
