/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_ESTABLISHMENT_REQUEST_H_
#define _PDU_SESSION_ESTABLISHMENT_REQUEST_H_

#include "Nas5gsmMessage.hpp"
#include "NasIeHeader.hpp"

namespace oai::nas {

class PduSessionEstablishmentRequest : public Nas5gsmMessage {
 public:
  PduSessionEstablishmentRequest();
  virtual ~PduSessionEstablishmentRequest();

  int Encode(uint8_t* buf, int len) override;
  int Decode(uint8_t* buf, int len) override;

  uint32_t GetLength() const override;

  void SetPduSessionIdentity(uint8_t pdu_session_id);
  uint8_t GetPduSessionIdentity() const;

  void SetProcedureTransactionIdentity(uint16_t procedure_transaction_id);
  uint16_t GetProcedureTransactionIdentity() const;

  void SetIntegrityProtectionMaximumDataRate(
      const IntegrityProtectionMaximumDataRate& rate);
  IntegrityProtectionMaximumDataRate GetIntegrityProtectionMaximumDataRate()
      const;

  void SetPduSessionType(const PduSessionType& type);
  std::optional<PduSessionType> GetPduSessionType() const;

  void SetSscMode(const SscMode ssc_mode);
  std::optional<SscMode> GetSscMode() const;

  void Set5gsmCapability(const _5gsmCapability& _5gsm_capability);
  std::optional<_5gsmCapability> Get5gsmCapability() const;

  void SetMaximumNumberOfSupportedPacketFilters(
      const MaximumNumberOfSupportedPacketFilters& filters);
  std::optional<MaximumNumberOfSupportedPacketFilters>
  GetMaximumNumberOfSupportedPacketFilters();

  void SetAlwaysOnPduSessionRequested(const AlwaysOnPduSessionRequested& apsr);
  std::optional<AlwaysOnPduSessionRequested> GetAlwaysOnPduSessionRequested()
      const;

  void SetPduDnRequestContainer(const PduDnRequestContainer& container);
  std::optional<PduDnRequestContainer> GetPduDnRequestContainer() const;

  void SetExtendedProtocolConfigurationOptions(
      const ExtendedProtocolConfigurationOptions& options);
  std::optional<ExtendedProtocolConfigurationOptions>
  GetExtendedProtocolConfigurationOptions() const;

  void SetIpHeaderCompressionConfiguration(
      const IpHeaderCompressionConfiguration& configuration);
  std::optional<IpHeaderCompressionConfiguration>
  GetIpHeaderCompressionConfiguration() const;

 private:
  IntegrityProtectionMaximumDataRate
      ie_integrity_protection_maximum_data_rate_;      // Mandatory
  std::optional<PduSessionType> ie_pdu_session_type_;  // Optional
  std::optional<SscMode> ie_ssc_mode_;                 // Optional
  std::optional<_5gsmCapability> ie_5gsm_capability_;  // Optional

  std::optional<MaximumNumberOfSupportedPacketFilters>
      ie_maximum_number_of_supported_packet_filters_;  // Optional
  std::optional<AlwaysOnPduSessionRequested>
      ie_always_on_pdu_session_requested_;  // Optional
  std::optional<PduDnRequestContainer>
      ie_pdu_dn_request_container_;  // Optional
  std::optional<ExtendedProtocolConfigurationOptions>
      ie_extended_protocol_configuration_options_;  // Optional
  std::optional<IpHeaderCompressionConfiguration>
      ie_ip_header_compression_configuration_;  // Optional
  // TODO: DS-TT Ethernet port MAC address
  // TODO: UE-DS-TT residence time
  // TODO: Port management information container
  // TODO: Ethernet header compression configuration
  // TODO: Suggested interface identifier
};

}  // namespace oai::nas

#endif
