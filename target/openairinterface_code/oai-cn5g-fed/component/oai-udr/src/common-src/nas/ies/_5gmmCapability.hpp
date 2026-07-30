/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _5GMM_CAPABILITY_H_
#define _5GMM_CAPABILITY_H_

#include "Type4NasIe.hpp"

constexpr uint8_t k5gmmCapabilityMinimumLength = 3;
constexpr uint8_t k5gmmCapabilityContentMinimumLength =
    k5gmmCapabilityMinimumLength -
    2;  // Minimum length - 2 octets for IEI/Length
constexpr uint8_t k5gmmCapabilityMaximumLength = 15;
constexpr auto k5gmmCapabilityIeName           = "5GMM Capability";

namespace oai::nas {

class _5gmmCapability : public Type4NasIe {
 public:
  _5gmmCapability();
  _5gmmCapability(uint8_t iei, uint8_t octet3);
  virtual ~_5gmmCapability();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = true) override;

  static std::string GetIeName() { return k5gmmCapabilityIeName; }

  void SetOctet3(uint8_t iei, uint8_t octet3);
  uint8_t GetOctet3() const;

 private:
  uint8_t octet3_;  // minimum length of 3 octets
  std::optional<uint8_t> octet4_;
  std::optional<uint8_t> octet5_;
  // TODO: octets 6-15
};

}  // namespace oai::nas

#endif
