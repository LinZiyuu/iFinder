/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _SECURITY_RESULT_H_
#define _SECURITY_RESULT_H_

#include "ConfidentialityProtectionResult.hpp"
#include "IntegrityProtectionResult.hpp"

extern "C" {
#include "Ngap_SecurityResult.h"
}

namespace oai::ngap {

class SecurityResult {
 public:
  SecurityResult();
  virtual ~SecurityResult();

  void set(
      const IntegrityProtectionResult& integrityProtectionResult,
      const ConfidentialityProtectionResult& confidentialityProtectionResult);
  bool get(
      IntegrityProtectionResult& integrityProtectionResult,
      ConfidentialityProtectionResult& confidentialityProtectionResult) const;

  bool encode(Ngap_SecurityResult_t&) const;
  bool decode(const Ngap_SecurityResult_t&);

 private:
  IntegrityProtectionResult m_IntegrityProtectionResult;  // Mandatory
  ConfidentialityProtectionResult
      m_ConfidentialityProtectionResult;  // Mandatory
};

}  // namespace oai::ngap

#endif
