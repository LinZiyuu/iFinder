/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _AUTHENTICATION_FAILURE_PARAMETER_H_
#define _AUTHENTICATION_FAILURE_PARAMETER_H_

#include "Type4NasIe.hpp"

constexpr uint8_t kAuthenticationFailureParameterLength = 16;
constexpr uint8_t kAuthenticationFailureParameterContentLength =
    kAuthenticationFailureParameterLength -
    2;  // Minimum length - 2 bytes for IEI/Length
constexpr auto kAuthenticationFailureParameterIeName =
    "Authentication Failure Parameter";

namespace oai::nas {

class AuthenticationFailureParameter : public Type4NasIe {
 public:
  AuthenticationFailureParameter();
  AuthenticationFailureParameter(const bstring& value);
  virtual ~AuthenticationFailureParameter() = default;

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() {
    return kAuthenticationFailureParameterIeName;
  }
  void SetValue(const bstring& value);
  void GetValue(bstring& value) const;

 private:
  bstring value_;
};

}  // namespace oai::nas

#endif
