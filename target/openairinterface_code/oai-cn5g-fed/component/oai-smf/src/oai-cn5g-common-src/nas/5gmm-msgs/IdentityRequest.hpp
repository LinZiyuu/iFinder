/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _IDENTITY_REQUEST_H_
#define _IDENTITY_REQUEST_H_

#include "NasIeHeader.hpp"
#include "NasMmPlainHeader.hpp"

namespace oai::nas {

class IdentityRequest : public Nas5gmmMessage {
 public:
  IdentityRequest();
  ~IdentityRequest();

  int Encode(uint8_t* buf, int len) override;
  int Decode(uint8_t* buf, int len) override;

  uint32_t GetLength() const override;

  void SetHeader(uint8_t security_header_type);

  void Set5gsIdentityType(uint8_t value);
  // TODO: Get

 private:
  NasMmPlainHeader ie_header_;             // Mandatory
  _5gsIdentityType ie_5gs_identity_type_;  // Mandatory
  // Spare half octet (Mandatory)
};

}  // namespace oai::nas

#endif
