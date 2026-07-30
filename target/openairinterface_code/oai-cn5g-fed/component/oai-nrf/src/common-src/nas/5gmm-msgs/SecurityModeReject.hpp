/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _SECURITY_MODE_REJECT_H_
#define _SECURITY_MODE_REJECT_H_

#include "NasIeHeader.hpp"
#include "NasMmPlainHeader.hpp"

namespace oai::nas {

class SecurityModeReject : public Nas5gmmMessage {
 public:
  SecurityModeReject();
  ~SecurityModeReject();

  int Encode(uint8_t* buf, int len) override;
  int Decode(uint8_t* buf, int len) override;

  uint32_t GetLength() const override;

  void SetHeader(uint8_t security_header_type);

  void Set5gmmCause(uint8_t value);
  // TODO: Get

 private:
  NasMmPlainHeader ie_header_;  // Mandatory
  _5gmmCause ie_5gmm_cause_;    // Mandatory
};

}  // namespace oai::nas

#endif
