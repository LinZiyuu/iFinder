/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _AUTHENTICATION_RESPONSE_PARAMETER_H_
#define _AUTHENTICATION_RESPONSE_PARAMETER_H_

#include "Type4NasIe.hpp"

constexpr uint8_t kAuthenticationResponseParameterMinimumLength = 6;
constexpr uint8_t kAuthenticationResponseParameterContentMinimumLength =
    kAuthenticationResponseParameterMinimumLength -
    2;  // Minimum length - 2 octets for IEI/Length
constexpr uint8_t kAuthenticationResponseParameterMaximumLength = 18;
constexpr auto kAuthenticationResponseParameterIeName =
    "Authentication Response Parameter";

namespace oai::nas {

class AuthenticationResponseParameter : public Type4NasIe {
 public:
  AuthenticationResponseParameter();
  AuthenticationResponseParameter(const bstring& para);
  virtual ~AuthenticationResponseParameter();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() {
    return kAuthenticationResponseParameterIeName;
  }

  void SetValue(const bstring& para);
  void GetValue(bstring& para) const;

 private:
  bstring res_or_res_star_;
};

}  // namespace oai::nas

#endif
