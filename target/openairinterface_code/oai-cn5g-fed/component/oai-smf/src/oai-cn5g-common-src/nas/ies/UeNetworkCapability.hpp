/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _UE_NETWORK_CAPABILITY_H
#define _UE_NETWORK_CAPABILITY_H

#include "Type4NasIe.hpp"

constexpr uint8_t kUeNetworkCapabilityMinimumLength = 4;
constexpr uint8_t kUeNetworkCapabilityContentMinimumLength =
    kUeNetworkCapabilityMinimumLength -
    2;  // Minimum length - 2 octets for IEI/Length
constexpr uint8_t kUeNetworkCapabilityMaximumLength = 15;
constexpr auto kUeNetworkCapabilityIeName           = "UE Network Capability";

namespace oai::nas {

class UeNetworkCapability : public Type4NasIe {
 public:
  UeNetworkCapability();
  UeNetworkCapability(uint8_t iei);
  UeNetworkCapability(uint8_t iei, uint8_t eea, uint8_t eia);
  virtual ~UeNetworkCapability();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = true);

  static std::string GetIeName() { return kUeNetworkCapabilityIeName; }

  void SetEea(uint8_t value);
  void SetEia(uint8_t value);

  uint8_t GetEea() const;
  uint8_t GetEia() const;

 private:
  uint8_t eea_;  // Mandatory
  uint8_t eia_;  // Mandatory
  // TODO: uint8_t uea_; //Optional
  // TODO: uint8_t uia_; //Optional
  // TODO: uint8_t octet7_; //Optional
  // TODO: uint8_t octet8_;//Optional
  // TODO: uint8_t octet9_; //Optional
  // TODO: spare octet 10-15
};

}  // namespace oai::nas

#endif
