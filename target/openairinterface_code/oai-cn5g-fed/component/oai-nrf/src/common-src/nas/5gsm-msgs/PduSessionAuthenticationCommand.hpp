/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_AUTHENTICATION_COMMAND_H_
#define _PDU_SESSION_AUTHENTICATION_COMMAND_H_

#include "Nas5gsmMessage.hpp"
#include "NasIeHeader.hpp"

namespace oai::nas {

class PduSessionAuthenticationCommand : public Nas5gsmMessage {
 public:
  PduSessionAuthenticationCommand();
  virtual ~PduSessionAuthenticationCommand();

  int Encode(uint8_t* buf, int len) override;
  int Decode(uint8_t* buf, int len) override;

  uint32_t GetLength() const override;

  void SetEapMessage(const EapMessage& eap_message);
  void GetEapMessage(EapMessage& eap_message) const;

  void SetExtendedProtocolConfigurationOptions(
      const ExtendedProtocolConfigurationOptions& options);
  void GetExtendedProtocolConfigurationOptions(
      std::optional<ExtendedProtocolConfigurationOptions>& options) const;

 private:
  // Nas5gsmHeader ie_header_;    // Mandatory
  EapMessage ie_eap_message_;  // Mandatory

  std::optional<ExtendedProtocolConfigurationOptions>
      ie_extended_protocol_configuration_options_;  // Optional
};

}  // namespace oai::nas

#endif
