/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _CONFIDENTIALITY_PROTECTION_RESULT_H_
#define _CONFIDENTIALITY_PROTECTION_RESULT_H_

extern "C" {
#include "Ngap_ConfidentialityProtectionResult.h"
}

namespace oai::ngap {

class ConfidentialityProtectionResult {
 public:
  ConfidentialityProtectionResult();
  virtual ~ConfidentialityProtectionResult(){};

  void set(const e_Ngap_ConfidentialityProtectionResult& value);
  bool get(long& value) const;

  bool encode(Ngap_ConfidentialityProtectionResult_t&) const;
  bool decode(const Ngap_ConfidentialityProtectionResult_t&);

 private:
  long m_ConfidentialityProtectionResult;
};

}  // namespace oai::ngap

#endif
