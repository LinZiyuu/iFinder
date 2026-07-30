/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _UE_SECURITY_CAPABILITIES_H_
#define _UE_SECURITY_CAPABILITIES_H_

extern "C" {
#include "Ngap_UESecurityCapabilities.h"
}

namespace oai::ngap {

class UeSecurityCapabilities {
 public:
  UeSecurityCapabilities();
  virtual ~UeSecurityCapabilities();

  void set(
      uint16_t nr_encryption_algs, uint16_t integrityProtectionAlgorithms,
      uint16_t eutraEncryptionAlgorithms,
      uint16_t eutraIntegrityProtectionAlgorithms);
  bool get(
      uint16_t& nr_encryption_algs, uint16_t& integrityProtectionAlgorithms,
      uint16_t& eutraEncryptionAlgorithms,
      uint16_t& eutraIntegrityProtectionAlgorithms) const;

  bool encode(Ngap_UESecurityCapabilities_t&) const;
  bool decode(const Ngap_UESecurityCapabilities_t&);

 private:
  uint16_t m_NrEncryptionAlgorithms;              // Mandatory
  uint16_t m_IntegrityProtectionAlgorithms;       // Mandatory
  uint16_t m_EutraEncryptionAlgorithms;           // Mandatory
  uint16_t m_EutraIntegrityProtectionAlgorithms;  // Mandatory
};

}  // namespace oai::ngap

#endif
