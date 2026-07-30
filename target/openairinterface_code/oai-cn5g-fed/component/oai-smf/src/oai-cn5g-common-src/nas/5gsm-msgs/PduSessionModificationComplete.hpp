/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_MODIFICATION_COMPLETE_H_
#define _PDU_SESSION_MODIFICATION_COMPLETE_H_

#include "Nas5gsmMessage.hpp"
#include "NasIeHeader.hpp"

namespace oai::nas {

class PduSessionModificationComplete : public Nas5gsmMessage {
 public:
  PduSessionModificationComplete();
  virtual ~PduSessionModificationComplete();

  int Encode(uint8_t* buf, int len) override;
  int Decode(uint8_t* buf, int len) override;

  uint32_t GetLength() const override;

  void SetExtendedProtocolConfigurationOptions(
      const ExtendedProtocolConfigurationOptions& options);
  void GetExtendedProtocolConfigurationOptions(
      std::optional<ExtendedProtocolConfigurationOptions>& options) const;

 private:
  // Nas5gsmHeader ie_header_;  // Mandatory

  std::optional<ExtendedProtocolConfigurationOptions>
      ie_extended_protocol_configuration_options_;  // Optional
  // TODO: Port management information container // Optional
};

}  // namespace oai::nas

#endif
