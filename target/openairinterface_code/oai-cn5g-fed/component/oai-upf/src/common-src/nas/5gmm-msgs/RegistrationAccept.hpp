/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _REGISTRATION_ACCEPT_H_
#define _REGISTRATION_ACCEPT_H_

#include "NasIeHeader.hpp"
#include "NasMmPlainHeader.hpp"

namespace oai::nas {

class RegistrationAccept : public Nas5gmmMessage {
 public:
  RegistrationAccept();
  ~RegistrationAccept();

  int Encode(uint8_t* buf, int len) override;
  int Decode(uint8_t* buf, int len) override;

  uint32_t GetLength() const override;

  void SetHeader(uint8_t security_header_type);
  void GetSecurityHeaderType(uint8_t security_header_type);  // TODO
  bool VerifyHeader();                                       // TODO

  void Set5gsRegistrationResult(
      bool emergency, bool nssaa, bool sms, uint8_t value);
  // TODO: Get

  // 5GSMobileIdentity
  void SetSuciSupiFormatImsi(
      const std::string& mcc, const std::string& mnc,
      const std::string& routing_ind, uint8_t protection_sch_id,
      const std::string& msin);
  void SetSuciSupiFormatImsi(
      const std::string& mcc, const std::string& mnc,
      const std::string& routing_ind, uint8_t protection_sch_id, uint8_t hnpki,
      const std::string& msin);
  void Set5gGuti(
      const std::string& mcc, const std::string& mnc, uint8_t amf_region_id,
      uint16_t amf_set_id, uint8_t amf_pointer, uint32_t tmsi);
  void SetImeiImeisv();  // TODO:
  void Set5gSTmsi();     // TODO:
  // TODO: Get

  // Equivalent PLMNs
  void SetEquivalentPlmns(const std::vector<nas_plmn_t>& list);
  // TODO: Get

  void SetTaiList(const std::vector<p_tai_t>& tai_list);
  // TODO: Get

  void SetAllowedNssai(const std::vector<struct SNSSAI_s>& nssai);
  // TODO: Get

  void SetRejectedNssai(const std::vector<RejectedSNssai>& nssai);
  // TODO: Get

  void SetConfiguredNssai(const std::vector<struct SNSSAI_s>& nssai);
  // TODO: Get

  void Set5gsNetworkFeatureSupport(uint8_t value, uint8_t value2);
  // TODO: Get

  void SetPduSessionStatus(uint16_t value);
  // TODO: Get

  void SetPduSessionReactivationResult(uint16_t value);
  // TODO: Get

  void SetPduSessionReactivationResultErrorCause(
      uint8_t session_id, uint8_t value);
  // TODO: Get

  void SetLadnInformation(const LadnInformation& ladn_information);
  // TODO: Get

  void SetMicoIndication(bool sprti, bool raai);
  // TODO: Get

  void SetNetworkSlicingIndication(bool dcni, bool nssci);
  // TODO: Get

  void SetServiceAreaList(const std::vector<service_area_list_ie_t>& list);
  // TODO: Get

  void SetT3512Value(uint8_t unit, uint8_t value);
  // TODO: Get

  void SetNon3gppDeregistrationTimerValue(uint8_t value);
  // TODO: Get

  void SetT3502Value(uint8_t value);
  // TODO: Get

  // TODO: Emergency number list
  // TODO: Extended emergency number list

  void SetSorTransparentContainer(uint8_t header, const uint8_t (&value)[16]);
  // TODO: Get

  void SetEapMessage(const bstring& eap);
  // TODO: Get

  void SetNssaiInclusionMode(uint8_t value);
  // TODO: Get

  // TODO: Operator-defined access category definitions

  void Set5gsDrxParameters(uint8_t value);
  // TODO: Get

  void SetNon3gppNwProvidedPolicies(uint8_t value);
  // TODO: Get

  void SetEpsBearerContextsStatus(uint16_t value);
  // TODO: Get

  void SetExtendedDrxParameters(uint8_t paging_time, uint8_t value);
  // TODO: Get

  void SetT3447Value(uint8_t unit, uint8_t value);
  // TODO: Get

  void SetT3448Value(uint8_t unit, uint8_t value);
  // TODO: Get

  void SetT3324Value(uint8_t unit, uint8_t value);
  // TODO: Get

  void SetUeRadioCapabilityId(const bstring& value);
  // TODO: Get

  void SetPendingNssai(const std::vector<struct SNSSAI_s>& nssai);
  // TODO: Get

 private:
  NasMmPlainHeader ie_header_;                         // Mandatory
  _5gsRegistrationResult ie_5gs_registration_result_;  // Mandatory

  std::optional<_5gsMobileIdentity> ie_5g_guti_;       // Optional
  std::optional<PlmnList> ie_equivalent_plmns_;        // Optional
  std::optional<_5gsTrackingAreaIdList> ie_tai_list_;  // Optional
  std::optional<Nssai> ie_allowed_nssai_;              // Optional
  std::optional<RejectedNssai> ie_rejected_nssai_;     // Optional
  std::optional<Nssai> ie_configured_nssai_;           // Optional
  std::optional<_5gsNetworkFeatureSupport>
      ie_5gs_network_feature_support_;                     // Optional
  std::optional<PduSessionStatus> ie_pdu_session_status_;  // Optional
  std::optional<PduSessionReactivationResult>
      ie_pdu_session_reactivation_result_;  // Optional
  std::optional<PduSessionReactivationResultErrorCause>
      ie_pdu_session_reactivation_result_error_cause_;  // Optional
  std::optional<LadnInformation> ie_ladn_information_;  //
  // Optional
  std::optional<MicoIndication> ie_mico_indication_;  // Optional
  std::optional<NetworkSlicingIndication>
      ie_network_slicing_indication_;                    // Optional
  std::optional<ServiceAreaList> ie_service_area_list_;  // Optional
  std::optional<GprsTimer3> ie_t3512_value_;             // Optional
  std::optional<GprsTimer2>
      ie_non_3gpp_deregistration_timer_value_;  // Optional
  std::optional<GprsTimer2> ie_t3502_value_;    // Optional
  // TODO: Emergency number list
  // TODO: Extended emergency number list
  std::optional<SorTransparentContainer>
      ie_sor_transparent_container_;                           // Optional
  std::optional<EapMessage> ie_eap_message_;                   // Optional
  std::optional<NssaiInclusionMode> ie_nssai_inclusion_mode_;  // Optional
  // TODO: Operator-defined access category definitions
  std::optional<_5gsDrxParameters> ie_negotiated_drx_parameters_;  // Optional
  std::optional<Non3gppNwProvidedPolicies>
      ie_non_3gpp_nw_policies_;  // Optional
  std::optional<EpsBearerContextStatus>
      ie_eps_bearer_context_status_;                                 // Optional
  std::optional<ExtendedDrxParameters> ie_extended_drx_parameters_;  // Optional
  std::optional<GprsTimer3> ie_t3447_value_;                         // Optional
  std::optional<GprsTimer3> ie_t3448_value_;                         // Optional
  std::optional<GprsTimer3> ie_t3324_value_;                         // Optional
  std::optional<UeRadioCapabilityId>
      ie_ue_radio_capability_id_;  // Release 16.4.1
  // TODO: UE radio capability ID deletion indication
  std::optional<Nssai> ie_pending_nssai_;  // Release 16.4.1
  // TODO: Ciphering key data (Release 16.4.1)
  // TODO: CAG information list (Release 16.4.1)
  // TODO: Truncated 5G-S-TMSI configuration (Release 16.4.1)
  // TODO: Negotiated WUS assistance information (Release 16.4.1)
  // TODO: Negotiated NB-N1 mode DRX parameters (Release 16.14.0)
};

}  // namespace oai::nas

#endif
