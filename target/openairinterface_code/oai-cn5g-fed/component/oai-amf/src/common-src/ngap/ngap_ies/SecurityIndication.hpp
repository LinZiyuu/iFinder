/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _SECURITY_INDICATION_H_
#define _SECURITY_INDICATION_H_

#include <optional>

#include "ConfidentialityProtectionIndication.hpp"
#include "IntegrityProtectionIndication.hpp"
#include "MaximumIntegrityProtectedDataRate.hpp"

extern "C" {
#include "Ngap_SecurityIndication.h"
}

namespace oai::ngap {

class SecurityIndication {
 public:
  SecurityIndication();
  SecurityIndication(
      const IntegrityProtectionIndication& integrityProtectionIndication,
      const ConfidentialityProtectionIndication&
          confidentialityProtectionIndication,
      const std::optional<MaximumIntegrityProtectedDataRate>&
          maximumIntegrityProtectedDataRateUl,
      const std::optional<MaximumIntegrityProtectedDataRate>&
          maximumIntegrityProtectedDataRateDl);
  virtual ~SecurityIndication();

  void set(
      const IntegrityProtectionIndication& integrityProtectionIndication,
      const ConfidentialityProtectionIndication&
          confidentialityProtectionIndication,
      const std::optional<MaximumIntegrityProtectedDataRate>&
          maximumIntegrityProtectedDataRateUl,
      const std::optional<MaximumIntegrityProtectedDataRate>&
          maximumIntegrityProtectedDataRateDl);

  void get(
      IntegrityProtectionIndication& integrityProtectionIndication,
      ConfidentialityProtectionIndication& confidentialityProtectionIndication,
      std::optional<MaximumIntegrityProtectedDataRate>&
          maximumIntegrityProtectedDataRateUl,
      std::optional<MaximumIntegrityProtectedDataRate>&
          maximumIntegrityProtectedDataRateDl) const;

  bool encode(Ngap_SecurityIndication_t& securityIndication) const;
  bool decode(const Ngap_SecurityIndication_t& securityIndication);

 private:
  IntegrityProtectionIndication m_IntegrityProtectionIndication;  // Mandatory
  ConfidentialityProtectionIndication
      m_ConfidentialityProtectionIndication;  // Mandatory
  std::optional<MaximumIntegrityProtectedDataRate>
      m_MaximumIntegrityProtectedDataRateUl;  // Conditional
  std::optional<MaximumIntegrityProtectedDataRate>
      m_MaximumIntegrityProtectedDataRateDl;  // Optional
};

}  // namespace oai::ngap

#endif
