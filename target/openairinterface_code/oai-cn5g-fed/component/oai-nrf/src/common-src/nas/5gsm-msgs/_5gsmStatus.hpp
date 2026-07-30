/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef __5GSM_STATUS_H_
#define __5GSM_STATUS_H_

#include "Nas5gsmMessage.hpp"
#include "NasIeHeader.hpp"

namespace oai::nas {

class _5gsmStatus : public Nas5gsmMessage {
 public:
  _5gsmStatus();
  virtual ~_5gsmStatus();

  int Encode(uint8_t* buf, int len) override;
  int Decode(uint8_t* buf, int len) override;

  uint32_t GetLength() const override;

  void Set5gsmCause(const _5gsmCause& _5gsm_cause);
  void Get5gsmCause(_5gsmCause& _5gsm_cause) const;

 private:
  // Header is defined in Nas5gsmMessage
  _5gsmCause ie_5gsm_cause_;  // Mandatory
};

}  // namespace oai::nas

#endif
