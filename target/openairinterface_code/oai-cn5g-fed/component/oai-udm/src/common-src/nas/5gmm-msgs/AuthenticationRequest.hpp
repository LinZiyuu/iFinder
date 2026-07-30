/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _AUTHENTICATION_REQUEST_H_
#define _AUTHENTICATION_REQUEST_H_

#include "NasIeHeader.hpp"
#include "NasMmPlainHeader.hpp"

namespace oai::nas {
using namespace oai::nas;
class AuthenticationRequest : public Nas5gmmMessage {
 public:
  AuthenticationRequest();
  ~AuthenticationRequest();

  int Encode(uint8_t* buf, int len) override;
  int Decode(uint8_t* buf, int len) override;

  uint32_t GetLength() const override;

  void SetHeader(uint8_t security_header_type);

  void SetNgKsi(uint8_t tsc, uint8_t key_set_id);
  // TODO: Get

  void SetEapMessage(const bstring& eap);
  // TODO: Get

  void SetAbba(uint8_t length, uint8_t* value);
  // TODO: Get

  void SetAuthenticationParameterRand(
      uint8_t value[kAuthenticationParameterRandValueLength]);
  // TODO: Get

  void SetAuthenticationParameterAutn(
      uint8_t value[kAuthenticationParameterAutnValueLength]);
  // TODO: Get

 private:
  NasMmPlainHeader ie_header_;     // Mandatory
  NasKeySetIdentifier ie_ng_ksi_;  // Mandatory
  // Spare half octet (will be processed together with NgKSI)
  Abba ie_abba_;  // Mandatory

  std::optional<AuthenticationParameterRand>
      ie_authentication_parameter_rand_;  // Optional
  std::optional<AuthenticationParameterAutn>
      ie_authentication_parameter_autn_;      // Optional
  std::optional<EapMessage> ie_eap_message_;  // Optional
};

}  // namespace oai::nas

#endif
