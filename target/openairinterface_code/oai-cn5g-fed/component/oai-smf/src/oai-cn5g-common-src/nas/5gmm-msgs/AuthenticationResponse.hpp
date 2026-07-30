/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _AUTHENTICATION_RESPONSE_H_
#define _AUTHENTICATION_RESPONSE_H_

#include "NasIeHeader.hpp"
#include "NasMmPlainHeader.hpp"

namespace oai::nas {
using namespace oai::nas;

class AuthenticationResponse : public Nas5gmmMessage {
 public:
  AuthenticationResponse();
  ~AuthenticationResponse();

  int Encode(uint8_t* buf, int len) override;
  int Decode(uint8_t* buf, int len) override;

  uint32_t GetLength() const override;

  void SetHeader(uint8_t security_header_type);

  void SetAuthenticationResponseParameter(const bstring& para);
  bool GetAuthenticationResponseParameter(bstring& para) const;

  void SetEapMessage(const bstring& eap);
  bool GetEapMessage(bstring& eap) const;

 private:
  oai::nas::NasMmPlainHeader ie_header_;  // Mandatory
  std::optional<AuthenticationResponseParameter>
      ie_authentication_response_parameter_;  // Optional
  std::optional<EapMessage> ie_eap_message_;  // Optional
};

}  // namespace oai::nas

#endif
