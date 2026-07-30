/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RELEASE_COMPLETE_H_
#define _PDU_SESSION_RELEASE_COMPLETE_H_

#include "Nas5gsmMessage.hpp"
#include "NasIeHeader.hpp"

namespace oai::nas {

class PduSessionReleaseComplete : public Nas5gsmMessage {
 public:
  PduSessionReleaseComplete();
  virtual ~PduSessionReleaseComplete();

  int Encode(uint8_t* buf, int len) override;
  int Decode(uint8_t* buf, int len) override;

  uint32_t GetLength() const override;

  void Set5gsmCause(const _5gsmCause& _5gsm_cause);
  void Get5gsmCause(std::optional<_5gsmCause>& _5gsm_cause) const;

  void SetExtendedProtocolConfigurationOptions(
      const ExtendedProtocolConfigurationOptions& options);
  void GetExtendedProtocolConfigurationOptions(
      std::optional<ExtendedProtocolConfigurationOptions>& options) const;

 private:
  // Nas5gsmHeader ie_header_;  // Mandatory

  std::optional<_5gsmCause> ie_5gsm_cause_;  // Optional
  std::optional<ExtendedProtocolConfigurationOptions>
      ie_extended_protocol_configuration_options_;  // Optional
};

}  // namespace oai::nas

#endif
