/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _AUTHENTICATION_PARAMETER_RAND_H_
#define _AUTHENTICATION_PARAMETER_RAND_H_

#include "Type3NasIe.hpp"

constexpr uint8_t kAuthenticationParameterRandLength = 17;
constexpr uint8_t kAuthenticationParameterRandValueLength =
    kAuthenticationParameterRandLength - 1;
constexpr auto kAuthenticationParameterRandIeName =
    "Authentication Parameter RAND";

namespace oai::nas {

class AuthenticationParameterRand : public Type3NasIe {
 public:
  AuthenticationParameterRand();
  AuthenticationParameterRand(uint8_t iei);
  AuthenticationParameterRand(
      uint8_t iei, uint8_t value[kAuthenticationParameterRandValueLength]);
  virtual ~AuthenticationParameterRand();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return kAuthenticationParameterRandIeName; }
  uint32_t GetIeLength() const override;

 private:
  uint8_t value_[kAuthenticationParameterRandValueLength];
};

}  // namespace oai::nas

#endif
