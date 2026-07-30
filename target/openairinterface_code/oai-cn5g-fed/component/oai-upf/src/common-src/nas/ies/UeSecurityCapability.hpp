/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _UE_SECURITY_CAPABILITY_H
#define _UE_SECURITY_CAPABILITY_H

#include "Type4NasIe.hpp"

constexpr uint8_t kUeSecurityCapabilityMinimumLength = 4;
constexpr uint8_t kUeSecurityCapabilityContentMinimumLength =
    kUeSecurityCapabilityMinimumLength -
    2;  // Minimum length - 2 octets for IEI/Length
constexpr uint8_t kUeSecurityCapabilityMaximumLength = 10;
constexpr auto kUeSecurityCapabilityIeName           = "UE Security Capability";

namespace oai::nas {

class UeSecurityCapability : public Type4NasIe {
 public:
  UeSecurityCapability();
  UeSecurityCapability(uint8_t iei);
  UeSecurityCapability(uint8_t _5g_ea, uint8_t _5g_ia);
  UeSecurityCapability(uint8_t iei, uint8_t _5g_ea, uint8_t _5g_ia);
  UeSecurityCapability(
      uint8_t iei, uint8_t _5g_ea, uint8_t _5g_ia, uint8_t eea, uint8_t eia);
  UeSecurityCapability(
      uint8_t _5g_ea, uint8_t _5g_ia, uint8_t eea, uint8_t eia);
  virtual ~UeSecurityCapability();
  void operator=(const UeSecurityCapability& ue_security_capability);

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return kUeSecurityCapabilityIeName; }

  void SetEa(uint8_t value);
  uint8_t GetEa() const;

  void SetIa(uint8_t value);
  uint8_t GetIa() const;

  void SetEea(uint8_t value);
  bool GetEea(uint8_t& value) const;
  void GetEea(std::optional<uint8_t>& value) const;

  void SetEia(uint8_t value);
  bool GetEia(uint8_t& value) const;
  void GetEia(std::optional<uint8_t>& value) const;

  void SetOctet_7_8(uint16_t value);
  void GetOctet_7_8(std::optional<uint16_t>& value) const;

  void SetOctet_9_10(uint16_t value);
  void GetOctet_9_10(std::optional<uint16_t>& value) const;

  void Set(uint8_t _5g_ea, uint8_t _5g_ia);
  void Set(uint8_t _5g_ea, uint8_t _5g_ia, uint8_t eea, uint8_t eia);

 private:
  uint8_t _5g_ea_;                      // 3rd octet, Mandatory
  uint8_t _5g_ia_;                      // 4th octet, Mandatory
  std::optional<uint8_t> eea_;          // 5th octet, Optional
  std::optional<uint8_t> eia_;          // 6th octet, Optional
  std::optional<uint16_t> octet_7_8_;   // 7th, 8th octets, Optional
  std::optional<uint16_t> octet_9_10_;  // 9th, 10th octets, Optional
};

}  // namespace oai::nas

#endif
