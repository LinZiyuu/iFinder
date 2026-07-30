/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_MODIFICATION_COMMAND_H_
#define _PDU_SESSION_MODIFICATION_COMMAND_H_

#include "Nas5gsmMessage.hpp"
#include "NasIeHeader.hpp"

namespace oai::nas {

class PduSessionModificationCommand : public Nas5gsmMessage {
 public:
  PduSessionModificationCommand();
  virtual ~PduSessionModificationCommand();

  int Encode(uint8_t* buf, int len) override;
  int Decode(uint8_t* buf, int len) override;

  uint32_t GetLength() const override;

  void Set5gsmCause(const _5gsmCause& _5gsm_cause);
  void Get5gsmCause(std::optional<_5gsmCause>& _5gsm_cause) const;

  void SetSessionAmbr(const SessionAmbr& session_ambr);
  void GetSessionAmbr(std::optional<SessionAmbr>& session_ambr) const;

  void SetRqTimerValue(const GprsTimer& gprs_timer);
  void GetRqTimerValue(std::optional<GprsTimer>& gprs_timer) const;

  void SetAlwaysOnPduSessionIndication(
      const AlwaysOnPduSessionIndication& always_on_pdu_session_indication);
  void GetAlwaysOnPduSessionIndication(
      std::optional<AlwaysOnPduSessionIndication>&
          always_on_pdu_session_indication) const;

  void SetAuthorizedQosRules(const QosRules& qos_rules);
  void GetAuthorizedQosRules(std::optional<QosRules>& qos_rules) const;

  // TODO: Mapped EPS bearer contexts

  void SetAuthorizedQosFlowDescriptions(
      const QosFlowDescriptions& flow_descriptions);
  void GetAuthorizedQosFlowDescriptions(
      std::optional<QosFlowDescriptions>& flow_descriptions) const;

  void SetExtendedProtocolConfigurationOptions(
      const ExtendedProtocolConfigurationOptions& options);
  void GetExtendedProtocolConfigurationOptions(
      std::optional<ExtendedProtocolConfigurationOptions>& options) const;

  // TODO: ATSSS container
  // TODO: IP header compression configuration
  // TODO: Port management information container
  // TODO: Serving PLMN rate control
  // TODO: Ethernet header compression configuration

 private:
  // Nas5gsmHeader ie_header_;  // Mandatory

  std::optional<_5gsmCause> ie_5gsm_cause_;  // Optional
  std::optional<SessionAmbr> ie_session_ambr_;
  std::optional<GprsTimer> ie_rq_timer_value_;  // Optional
  std::optional<AlwaysOnPduSessionIndication>
      ie_always_on_pdu_session_indication_;          // Optional
  std::optional<QosRules> ie_authorized_qos_rules_;  // Optional
  // TODO:Mapped EPS bearer contexts
  std::optional<QosFlowDescriptions>
      ie_authorized_qos_flow_descriptions_;  // Optional
  std::optional<ExtendedProtocolConfigurationOptions>
      ie_extended_protocol_configuration_options_;  // Optional

  // TODO: ATSSS container  // Optional
  // TODO: IP header compression configuration  // Optional
  // TODO: Port management information container
  // TODO: Serving PLMN rate control // Optional
  // TODO: Ethernet header compression configuration  // Optional
};

}  // namespace oai::nas

#endif
