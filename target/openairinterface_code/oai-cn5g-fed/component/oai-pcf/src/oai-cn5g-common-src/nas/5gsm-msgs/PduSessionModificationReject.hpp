/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_MODIFICATION_REJECT_H_
#define _PDU_SESSION_MODIFICATION_REJECT_H_

#include "Nas5gsmMessage.hpp"
#include "NasIeHeader.hpp"

namespace oai::nas {

class PduSessionModificationReject : public Nas5gsmMessage {
 public:
  PduSessionModificationReject();
  virtual ~PduSessionModificationReject();

  int Encode(uint8_t* buf, int len) override;
  int Decode(uint8_t* buf, int len) override;

  uint32_t GetLength() const override;

  void Set5gsmCause(const _5gsmCause& _5gsm_cause);
  void Get5gsmCause(_5gsmCause& _5gsm_cause) const;

  void SetBackOffTimerValue(const GprsTimer3& back_off_timer_value);
  void GetBackOffTimerValue(
      std::optional<GprsTimer3>& back_off_timer_value) const;

  void Set5gsmCongestionReAttemptIndicator(
      const _5gsmCongestionReAttemptIndicator& indicator);
  void Get5gsmCongestionReAttemptIndicator(
      std::optional<_5gsmCongestionReAttemptIndicator>& indicator) const;

  void SetExtendedProtocolConfigurationOptions(
      const ExtendedProtocolConfigurationOptions& options);
  void GetExtendedProtocolConfigurationOptions(
      std::optional<ExtendedProtocolConfigurationOptions>& options) const;

  void SetReAttemptIndicator(const ReAttemptIndicator& re_attempt_indicator);
  void GetReAttemptIndicator(
      std::optional<ReAttemptIndicator>& re_attempt_indicator) const;

 private:
  // Nas5gsmHeader ie_header_;   // Mandatory
  _5gsmCause ie_5gsm_cause_;  // Mandatory

  std::optional<GprsTimer3> ie_back_off_timer_value_;  // Optional
  std::optional<_5gsmCongestionReAttemptIndicator>
      ie_5gsm_congestion_re_attempt_indicator_;  // Optional
  std::optional<ExtendedProtocolConfigurationOptions>
      ie_extended_protocol_configuration_options_;             // Optional
  std::optional<ReAttemptIndicator> ie_re_attempt_indicator_;  // Optional
};

}  // namespace oai::nas

#endif
