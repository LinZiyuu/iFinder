/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _AUTHENTICATION_FAILURE_H_
#define _AUTHENTICATION_FAILURE_H_

#include "NasIeHeader.hpp"
#include "NasMmPlainHeader.hpp"

namespace oai::nas {
using namespace oai::nas;

class AuthenticationFailure : public Nas5gmmMessage {
 public:
  AuthenticationFailure();
  virtual ~AuthenticationFailure() = default;

  int Encode(uint8_t* buf, int len) override;
  int Decode(uint8_t* buf, int len) override;

  uint32_t GetLength() const override;

  void SetHeader(uint8_t security_header_type);

  void Set5gmmCause(uint8_t value);
  uint8_t Get5gmmCause() const;

  //  void SetAuthenticationFailureParameter(const uint8_t
  //  (&value)[kAuthenticationFailureParameterContentLength]); bool
  //  GetAuthenticationFailureParameter(uint8_t
  //  (&value)[kAuthenticationFailureParameterContentLength]) const;

  void SetAuthenticationFailureParameter(const bstring& value);
  bool GetAuthenticationFailureParameter(bstring& value) const;

 private:
  NasMmPlainHeader ie_header_;  // Mandatory
  _5gmmCause ie_5gmm_cause_;    // Mandatory
  std::optional<AuthenticationFailureParameter>
      ie_authentication_failure_parameter_;  // Optional
};

}  // namespace oai::nas

#endif
