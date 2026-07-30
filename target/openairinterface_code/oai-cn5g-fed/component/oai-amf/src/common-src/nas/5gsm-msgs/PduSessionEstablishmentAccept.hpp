/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_ESTABLISHMENT_ACCEPT_H_
#define _PDU_SESSION_ESTABLISHMENT_ACCEPT_H_

#include "Nas5gsmMessage.hpp"
#include "NasIeHeader.hpp"

namespace oai::nas {

class PduSessionEstablishmentAccept : public Nas5gsmMessage {
 public:
  PduSessionEstablishmentAccept();
  virtual ~PduSessionEstablishmentAccept();

  int Encode(uint8_t* buf, int len) override;
  int Decode(uint8_t* buf, int len) override;

  uint32_t GetLength() const override;

  void SetSelectedPduSessionType(const PduSessionType& pdu_session_type);
  void GetSelectedPduSessionType(PduSessionType& pdu_session_type) const;

  void SetSelectedSscMode(const SscMode& ssc_mode);
  void GetSelectedSscMode(SscMode& ssc_mode) const;

  void SetAuthorizedQosRules(const QosRules& qos_rules);
  void GetAuthorizedQosRules(QosRules& qos_rules) const;

  void SetSessionAmbr(const SessionAmbr& session_ambr);
  void GetSessionAmbr(SessionAmbr& session_ambr) const;

  void Set5gsmCause(const _5gsmCause& _5gsm_cause);
  void Get5gsmCause(std::optional<_5gsmCause>& _5gsm_cause) const;

  void SetPduAddress(const PduAddress& pdu_address);
  void GetPduAddress(std::optional<PduAddress>& pdu_address) const;

  void SetRqTimerValue(const GprsTimer& gprs_timer);
  void GetRqTimerValue(std::optional<GprsTimer>& gprs_timer) const;

  void SetSNssai(const SNssai& snssai);
  void GetSNssai(std::optional<SNssai>& snssai) const;

  void SetAlwaysOnPduSessionIndication(
      const AlwaysOnPduSessionIndication& always_on_pdu_session_indication);
  void GetAlwaysOnPduSessionIndication(
      std::optional<AlwaysOnPduSessionIndication>&
          always_on_pdu_session_indication) const;

  void SetEapMessage(const EapMessage& eap_message);
  void GetEapMessage(std::optional<EapMessage>& eap_message) const;

  void SetAuthorizedQosFlowDescriptions(
      const QosFlowDescriptions& flow_descriptions);
  void GetAuthorizedQosFlowDescriptions(
      std::optional<QosFlowDescriptions>& flow_descriptions) const;

  void SetExtendedProtocolConfigurationOptions(
      const ExtendedProtocolConfigurationOptions& options);
  void GetExtendedProtocolConfigurationOptions(
      std::optional<ExtendedProtocolConfigurationOptions>& options) const;

  void SetDnn(const Dnn& dnn);
  void GetDnn(std::optional<Dnn>& dnn) const;

 private:
  // Nas5gsmHeader ie_header_;                      // Mandatory
  PduSessionType ie_selected_pdu_session_type_;  // Mandatory
  SscMode ie_selected_ssc_mode_;                 // Mandatory
  QosRules ie_authorized_qos_rules_;             // Mandatory
  SessionAmbr ie_session_ambr_;                  // Mandatory

  std::optional<_5gsmCause> ie_5gsm_cause_;   // Optional
  std::optional<PduAddress> ie_pdu_address_;  // Optional
  std::optional<GprsTimer> ie_gprs_timer_;    // Optional
  std::optional<SNssai> ie_s_nssai_;          // Optional
  std::optional<AlwaysOnPduSessionIndication>
      ie_always_on_pdu_session_indication_;  // Optional
  // TODO: Mapped EPS bearer contexts  // Optional
  std::optional<EapMessage> ie_eap_message_;  // Optional
  std::optional<QosFlowDescriptions>
      ie_authorized_qos_flow_descriptions_;  // Optional
  std::optional<ExtendedProtocolConfigurationOptions>
      ie_extended_protocol_configuration_options_;  // Optional
  std::optional<Dnn> ie_dnn_;                       // Optional
  // TODO: 5GSM network feature support  // Optional
  // TODO: Serving PLMN rate control  // Optional
  // TODO: ATSSS container  // Optional
  // TODO: Control plane only indication  // Optional
  // TODO: IP header compression configuration  // Optional
  // TODO: Ethernet header compression configuration  // Optional
};

}  // namespace oai::nas

#endif
