/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_MODIFICATION_REQUEST_H_
#define _PDU_SESSION_MODIFICATION_REQUEST_H_

#include "Nas5gsmMessage.hpp"
#include "NasIeHeader.hpp"

namespace oai::nas {

class PduSessionModificationRequest : public Nas5gsmMessage {
 public:
  PduSessionModificationRequest();
  virtual ~PduSessionModificationRequest();

  int Encode(uint8_t* buf, int len) override;
  int Decode(uint8_t* buf, int len) override;

  uint32_t GetLength() const override;

  void Set5gsmCapability(const _5gsmCapability& _5gsm_capability);
  void Get5gsmCapability(
      std::optional<_5gsmCapability>& _5gsm_capability) const;

  void Set5gsmCause(const _5gsmCause& _5gsm_cause);
  void Get5gsmCause(std::optional<_5gsmCause>& _5gsm_cause) const;

  void SetMaximumNumberOfSupportedPacketFilters(
      const MaximumNumberOfSupportedPacketFilters& filters);

  void GetMaximumNumberOfSupportedPacketFilters(
      std::optional<MaximumNumberOfSupportedPacketFilters>& filters) const;

  void SetAlwaysOnPduSessionRequested(const AlwaysOnPduSessionRequested& apsr);
  void GetAlwaysOnPduSessionRequested(
      std::optional<AlwaysOnPduSessionRequested>& apsr) const;

  void SetIntegrityProtectionMaximumDataRate(
      const IntegrityProtectionMaximumDataRate& rate);
  void GetIntegrityProtectionMaximumDataRate(
      std::optional<IntegrityProtectionMaximumDataRate>& rate) const;

  void SetRequestedQosRules(const QosRules& qos_rules);
  void GetRequestedQosRules(std::optional<QosRules>& qos_rules) const;

  void SetRequestedQosFlowDescriptions(
      const QosFlowDescriptions& flow_descriptions);
  void GetRequestedQosFlowDescriptions(
      std::optional<QosFlowDescriptions>& flow_descriptions) const;

  void SetExtendedProtocolConfigurationOptions(
      const ExtendedProtocolConfigurationOptions& options);
  void GetExtendedProtocolConfigurationOptions(
      std::optional<ExtendedProtocolConfigurationOptions>& options) const;

 private:
  // Nas5gsmHeader ie_header_;  // Mandatory

  std::optional<_5gsmCapability> ie_5gsm_capability_;  // Optional
  std::optional<_5gsmCause> ie_5gsm_cause_;            // Optional
  std::optional<MaximumNumberOfSupportedPacketFilters>
      ie_maximum_number_of_supported_packet_filters_;  // Optional
  std::optional<AlwaysOnPduSessionRequested>
      ie_always_on_pdu_session_requested_;  // Optional
  std::optional<IntegrityProtectionMaximumDataRate>
      ie_integrity_protection_maximum_data_rate_;   // Optional
  std::optional<QosRules> ie_requested_qos_rules_;  // Mandatory
  std::optional<QosFlowDescriptions>
      ie_requested_qos_flow_descriptions_;  // Optional
  // TODO: Mapped EPS bearer contexts
  std::optional<ExtendedProtocolConfigurationOptions>
      ie_extended_protocol_configuration_options_;  // Optional
  // TODO: Port management information container
  // TODO: Header compression configuration
  // TODO: Ethernet header compression configuration
};

}  // namespace oai::nas

#endif
