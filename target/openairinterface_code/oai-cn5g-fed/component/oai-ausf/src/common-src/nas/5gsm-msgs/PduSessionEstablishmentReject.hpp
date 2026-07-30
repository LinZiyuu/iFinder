/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_ESTABLISHMENT_REJECT_H_
#define _PDU_SESSION_ESTABLISHMENT_REJECT_H_

#include "Nas5gsmMessage.hpp"
#include "NasIeHeader.hpp"

namespace oai::nas {

class PduSessionEstablishmentReject : public Nas5gsmMessage {
 public:
  PduSessionEstablishmentReject();
  virtual ~PduSessionEstablishmentReject();

  int Encode(uint8_t* buf, int len) override;
  int Decode(uint8_t* buf, int len) override;

  uint32_t GetLength() const override;

  void Set5gsmCause(const _5gsmCause& _5gsm_cause);
  void Get5gsmCause(_5gsmCause& _5gsm_cause) const;

  void SetBackOffTimerValue(const GprsTimer3& back_off_timer_value);
  void GetBackOffTimerValue(
      std::optional<GprsTimer3>& back_off_timer_value) const;

  void SetAllowedSscMode(const AllowedSscMode& allowed_ssc_mode);
  void GetAllowedSscMode(std::optional<AllowedSscMode>& allowed_ssc_mode) const;

  void SetEapMessage(const EapMessage& eap_message);
  void GetEapMessage(std::optional<EapMessage>& eap_message) const;

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
  std::optional<AllowedSscMode> ie_allowed_ssc_mode_;  // Optional
  std::optional<EapMessage> ie_eap_message_;           // Optional
  std::optional<_5gsmCongestionReAttemptIndicator>
      ie_5gsm_congestion_re_attempt_indicator_;  // Optional
  std::optional<ExtendedProtocolConfigurationOptions>
      ie_extended_protocol_configuration_options_;             // Optional
  std::optional<ReAttemptIndicator> ie_re_attempt_indicator_;  // Optional
};

}  // namespace oai::nas

#endif
