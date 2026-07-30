/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _5GSM_CAPABILITY_H_
#define _5GSM_CAPABILITY_H_

#include "Type4NasIe.hpp"

constexpr uint8_t k5gsmCapabilityMinimumLength = 3;
constexpr uint8_t k5gsmCapabilityContentMinimumLength =
    k5gsmCapabilityMinimumLength -
    2;  // Minimum length - 2 octets for IEI/Length
constexpr uint8_t k5gsmCapabilityMaximumLength = 15;
constexpr auto k5gsmCapabilityIeName           = "5GSM Capability";

namespace oai::nas {

class _5gsmCapability : public Type4NasIe {
 public:
  _5gsmCapability();
  _5gsmCapability(uint8_t iei, uint8_t octet3);
  virtual ~_5gsmCapability();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = true) override;

  static std::string GetIeName() { return k5gsmCapabilityIeName; }

  void SetOctet3(uint8_t iei, uint8_t octet3);
  uint8_t GetOctet3() const;

 private:
  uint8_t octet3_;  // minimum length of 3 octets
  // TODO: octets 4-15 (Spare)
};

}  // namespace oai::nas

#endif
