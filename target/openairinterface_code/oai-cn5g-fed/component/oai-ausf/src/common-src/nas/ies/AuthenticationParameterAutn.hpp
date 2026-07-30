/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */
#ifndef _AUTHENTICATION_PARAMETER_AUTN_H_
#define _AUTHENTICATION_PARAMETER_AUTN_H_

#include "Type4NasIe.hpp"

constexpr uint8_t kAuthenticationParameterAutnLength = 18;
constexpr uint8_t kAuthenticationParameterAutnValueLength =
    kAuthenticationParameterAutnLength - 2;
constexpr auto kAuthenticationParameterAutnIeName =
    "Authentication Parameter AUTN";

namespace oai::nas {

class AuthenticationParameterAutn : public Type4NasIe {
 public:
  AuthenticationParameterAutn();
  AuthenticationParameterAutn(uint8_t iei);
  AuthenticationParameterAutn(
      uint8_t iei, uint8_t value[kAuthenticationParameterAutnValueLength]);
  virtual ~AuthenticationParameterAutn();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return kAuthenticationParameterAutnIeName; }

 private:
  uint8_t value_[kAuthenticationParameterAutnValueLength];
};

}  // namespace oai::nas

#endif
