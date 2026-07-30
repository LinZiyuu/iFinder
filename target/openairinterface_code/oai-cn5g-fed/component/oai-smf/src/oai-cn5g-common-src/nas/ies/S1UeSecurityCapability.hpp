/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _S1_UE_SECURITY_CAPABILITY_H
#define _S1_UE_SECURITY_CAPABILITY_H

#include "Type4NasIe.hpp"

constexpr uint8_t kS1UeSecurityCapabilityMinimumLength = 4;
constexpr uint8_t kS1UeSecurityCapabilityContentMinimumLength =
    kS1UeSecurityCapabilityMinimumLength -
    2;  // Minimum length - 2 octets for IEI/Length
constexpr uint8_t kS1UeSecurityCapabilityMaximumLength = 7;
constexpr auto kS1UeSecurityCapabilityIeName = "S1 UE Security Capability";

namespace oai::nas {

class S1UeSecurityCapability : public Type4NasIe {
 public:
  S1UeSecurityCapability();
  S1UeSecurityCapability(uint8_t iei);
  S1UeSecurityCapability(uint8_t iei, uint8_t eea, uint8_t eia);
  S1UeSecurityCapability(
      uint8_t iei, uint8_t eea, uint8_t eia, uint8_t uea, uint8_t uia);
  virtual ~S1UeSecurityCapability();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return kS1UeSecurityCapabilityIeName; }

  void SetEea(uint8_t sel);
  uint8_t GetEea() const;

  void SetEia(uint8_t sel);
  uint8_t GetEia() const;

  void Set(uint8_t eea, uint8_t eia);
  void Get(uint8_t& eea, uint8_t& eia) const;

  void Set(uint8_t eea, uint8_t eia, uint8_t uea, uint8_t uia);
  void Get(uint8_t& eea, uint8_t& eia, uint8_t& uea, uint8_t& uia) const;

 private:
  uint8_t eea_;
  uint8_t eia_;
  std::optional<uint8_t> uea_;  // 5th octet, Optional
  std::optional<uint8_t> uia_;  // 6th octet, Optional
  std::optional<uint8_t> gea_;  // 7th octet, Optional
};

}  // namespace oai::nas

#endif
