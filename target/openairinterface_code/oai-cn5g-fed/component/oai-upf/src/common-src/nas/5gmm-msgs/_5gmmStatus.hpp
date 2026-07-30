/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef __5GMM_STATUS_H_
#define __5GMM_STATUS_H_

#include "NasIeHeader.hpp"
#include "NasMmPlainHeader.hpp"

namespace oai::nas {

class _5gmmStatus : public Nas5gmmMessage {
 public:
  _5gmmStatus();
  ~_5gmmStatus();

  int Encode(uint8_t* buf, int len) override;
  int Decode(uint8_t* buf, int len) override;

  uint32_t GetLength() const override;

  void SetHeader(uint8_t security_header_type);

  void Set5gmmCause(uint8_t value);
  uint8_t Get5gmmCause() const;

 private:
  NasMmPlainHeader ie_header_;  // Mandatory
  _5gmmCause ie_5gmm_cause_;    // Mandatory
};

}  // namespace oai::nas

#endif
