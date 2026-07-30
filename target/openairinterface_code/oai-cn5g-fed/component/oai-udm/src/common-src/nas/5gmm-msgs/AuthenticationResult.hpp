/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _AUTHENTICATION_RESULT_H_
#define _AUTHENTICATION_RESULT_H_

#include "NasIeHeader.hpp"
#include "NasMmPlainHeader.hpp"

namespace oai::nas {

class AuthenticationResult : public Nas5gmmMessage {
 public:
  AuthenticationResult();
  ~AuthenticationResult();

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

 private:
  NasMmPlainHeader ie_header_;     // Mandatory
  NasKeySetIdentifier ie_ng_ksi_;  // Mandatory (1/2 lower octet)
  EapMessage ie_eap_message_;      // Mandatory
  std::optional<Abba> ie_abba_;    // Optional
};

}  // namespace oai::nas

#endif
