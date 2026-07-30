/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _AUTHENTICATION_REJECT_H_
#define _AUTHENTICATION_REJECT_H_

#include "NasIeHeader.hpp"
#include "NasMmPlainHeader.hpp"

namespace oai::nas {
using namespace oai::nas;

class AuthenticationReject : public Nas5gmmMessage {
 public:
  AuthenticationReject();
  ~AuthenticationReject();

  int Encode(uint8_t* buf, int len) override;
  int Decode(uint8_t* buf, int len) override;

  uint32_t GetLength() const override;

  void SetHeader(uint8_t security_header_type);

  void SetEapMessage(const bstring& eap);
  // TODO: Get

 private:
  NasMmPlainHeader ie_header_;  // Mandatory
  std::optional<EapMessage> ie_eap_message_;
};

}  // namespace oai::nas

#endif
