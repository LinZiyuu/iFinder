/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _INTEGRITY_PROTECTION_RESULT_H_
#define _INTEGRITY_PROTECTION_RESULT_H_

extern "C" {
#include "Ngap_IntegrityProtectionResult.h"
}

namespace oai::ngap {

class IntegrityProtectionResult {
 public:
  IntegrityProtectionResult();
  virtual ~IntegrityProtectionResult();

  void set(const e_Ngap_IntegrityProtectionResult& value);
  bool get(long& value) const;

  bool encode(Ngap_IntegrityProtectionResult_t&) const;
  bool decode(const Ngap_IntegrityProtectionResult_t&);

 private:
  long m_Result;
};

}  // namespace oai::ngap

#endif
