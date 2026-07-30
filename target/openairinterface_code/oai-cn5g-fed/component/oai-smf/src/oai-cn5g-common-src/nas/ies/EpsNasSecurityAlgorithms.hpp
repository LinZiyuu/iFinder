/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _EPS_NAS_SECURITY_ALGORITHS_H
#define _EPS_NAS_SECURITY_ALGORITHS_H

#include "Type3NasIe.hpp"

constexpr uint8_t kEpsNasSecurityAlgorithmsLength = 2;
constexpr auto kEpsNasSecurityAlgorithmsIeName = "EPS NAS Security Algorithms";

namespace oai::nas {

class EpsNasSecurityAlgorithms : public Type3NasIe {
 public:
  EpsNasSecurityAlgorithms();
  EpsNasSecurityAlgorithms(uint8_t ciphering, uint8_t integrity_protection);
  virtual ~EpsNasSecurityAlgorithms();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return kEpsNasSecurityAlgorithmsIeName; }
  uint32_t GetIeLength() const override;

  void SetTypeOfCipheringAlgorithm(uint8_t value);
  uint8_t GetTypeOfCipheringAlgorithm() const;

  void SetTypeOfIntegrityProtectionAlgorithm(uint8_t value);
  uint8_t GetTypeOfIntegrityProtectionAlgorithm() const;

  void Set(uint8_t ciphering, uint8_t integrity_protection);
  void Get(uint8_t& ciphering, uint8_t& integrity_protection) const;

 private:
  uint8_t type_of_ciphering_algorithm_;
  uint8_t type_of_integrity_protection_algorithm_;
};

}  // namespace oai::nas

#endif
