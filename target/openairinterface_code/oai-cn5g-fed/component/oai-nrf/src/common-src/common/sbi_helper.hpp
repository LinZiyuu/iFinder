/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <boost/algorithm/string.hpp>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>

#include "common_defs.h"
#include "if.hpp"
#include "logger_base.hpp"
#include "string.hpp"

namespace oai::common::sbi {

using namespace oai::logger;

constexpr auto kNumberOfFirstConnectionRetries       = 10;
constexpr auto kNumberOfConnectionRetries            = 3;
constexpr auto kNfDefaultCurlTimeout                 = 1000;  // in Millisecond
constexpr auto kNumberOfCurlRetries                  = 3;
constexpr auto kBaseTimeIntervalBetweenCurlRetries   = 1000;  // in microsecond
constexpr auto kNumberOfNfRegisterRetries            = 3;
constexpr auto kNumberOfNfDeregisterRetries          = 3;
constexpr auto kTimeIntervalBetweenNfRegisterRetries = 1;    // in seconds
constexpr auto kTimeIntervalBetweenNfDeregisterRetries = 1;  // in seconds
constexpr auto kNfDefaultHttpRequestTimeout = 1000;          // in Millisecond

constexpr auto kDefaultSbiApiVersion = "v1";

typedef struct interface_cfg_s {
  std::string if_name;
  struct in_addr addr4;
  struct in_addr network4;
  struct in6_addr addr6;
  unsigned int mtu;
  unsigned int port;
  std::optional<std::string> api_version;

  nlohmann::json to_json() const {
    nlohmann::json json_data = {};
    json_data["if_name"]     = this->if_name;
    json_data["addr4"]       = inet_ntoa(this->addr4);
    json_data["network4"]    = inet_ntoa(this->network4);
    char str_addr6[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &this->addr6, str_addr6, sizeof(str_addr6));
    json_data["addr6"] = str_addr6;
    json_data["mtu"]   = this->mtu;
    json_data["port"]  = this->port;
    if (api_version.has_value())
      json_data["api_version"] = this->api_version.value();
    return json_data;
  }

  void from_json(nlohmann::json& json_data) {
    try {
      if (json_data.find("if_name") != json_data.end()) {
        this->if_name = json_data["if_name"].get<std::string>();
      }
      if (json_data.find("addr4") != json_data.end()) {
        std::string addr4_str = {};
        addr4_str             = json_data["addr4"].get<std::string>();
        if (boost::iequals(addr4_str, "read")) {
          if (oai::utils::get_inet_addr_infos_from_iface(
                  this->if_name, this->addr4, this->network4, this->mtu)) {
            logger_common::common().error(
                "Could not read %s network interface configuration",
                this->if_name);
            return;
          }
        } else {
          IPV4_STR_ADDR_TO_INADDR(
              oai::utils::trim(addr4_str).c_str(), this->addr4,
              "BAD IPv4 ADDRESS FORMAT FOR INTERFACE !");
          if (json_data.find("network4") != json_data.end()) {
            std::string network4_str = json_data["network4"].get<std::string>();
            IPV4_STR_ADDR_TO_INADDR(
                oai::utils::trim(network4_str).c_str(), this->network4,
                "BAD IPv4 ADDRESS FORMAT FOR INTERFACE !");
          }
          // TODO: addr6
          if (json_data.find("mtu") != json_data.end()) {
            this->mtu = json_data["mtu"].get<int>();
          }
          if (json_data.find("port") != json_data.end()) {
            this->port = json_data["port"].get<int>();
          }
          if (json_data.find("api_version") != json_data.end()) {
            this->api_version = std::make_optional<std::string>(
                json_data["api_version"].get<std::string>());
          }
        }
      }
    } catch (std::exception& e) {
      logger_common::common().error("%s", e.what());
    }
  }

  std::string get_ipv4_root() const {
    return std::string(inet_ntoa(this->addr4)) + ":" +
           std::to_string(this->port);
  }

} interface_cfg_t;

typedef struct nf_addr_s {
  struct in_addr ipv4_addr;
  unsigned int port;
  std::string api_version;
  std::string uri_root;

  nlohmann::json to_json() const {
    nlohmann::json json_data = {};
    json_data["uri_root"]    = this->uri_root;
    json_data["api_version"] = this->api_version;
    return json_data;
  }

  void from_json(nlohmann::json& json_data) {
    try {
      if (json_data.find("uri_root") != json_data.end()) {
        this->uri_root = json_data["uri_root"].get<std::string>();
      }
      if (json_data.find("api_version") != json_data.end()) {
        this->api_version = json_data["api_version"].get<std::string>();
      }
    } catch (std::exception& e) {
      logger_common::common().error("%s", e.what());
    }
  }

} nf_addr_t;

class sbi_helper {
 public:
  // AMF: Communication Service
  static inline const std::string AmfCommBase          = "/namf-comm/";
  static inline const std::string AmfCommPathUeContext = "/ue-contexts/";
  static inline const std::string AmfCommPathUeContextContextId =
      "/ue-contexts/:ueContextId";
  static inline const std::string AmfCommPathUeContextContextIdRelease =
      "/ue-contexts/:ueContextId/release";
  static inline const std::string AmfCommPathUeContextContextIdAssignEbi =
      "/ue-contexts/:ueContextId/assign-ebi";
  static inline const std::string AmfCommPathUeContextContextIdTransfer =
      "/ue-contexts/:ueContextId/transfer";
  static inline const std::string AmfCommPathUeContextContextIdTransferUpdate =
      "/ue-contexts/:ueContextId/transfer-update";
  static inline const std::string AmfCommPathUeContextContextIdRelocate =
      "/ue-contexts/:ueContextId/relocate";
  static inline const std::string AmfCommPathUeContextContextIdN1N2Message =
      "/ue-contexts/:ueContextId/n1-n2-messages";
  static inline const std::string AmfCommPathUeContextContextIdN1MessageNotify =
      "/ue-contexts/:ueContextId/n1-message-notify";
  static inline const std::string
      AmfCommPathUeContextContextIdN1N2MessageSubscriptions =
          "/ue-contexts/:ueContextId/n1-n2-messages/subscriptions";
  static inline const std::string
      AmfCommPathUeContextContextIdN1N2MessageSubscriptionsSubscriptionId =
          "/ue-contexts/:ueContextId/n1-n2-messages/subscriptions/"
          ":subscriptionId";
  static inline const std::string AmfCommPathNonUeN1N2MessageTransfer =
      "/non-ue-n2-messages/transfer";
  static inline const std::string AmfCommPathNonUeN1N2MessageSubscriptions =
      "/non-ue-n2-messages/subscriptions";
  static inline const std::string
      AmfCommPathNonUeN1N2MessageSubscriptionsn2NotifySubscriptionId =
          "/non-ue-n2-messages/subscriptions/:n2NotifySubscriptionId";
  static inline const std::string AmfCommPathSubscriptions = "/subscriptions";
  static inline const std::string AmfCommPathSubscriptionsSubscriptionId =
      "/subscriptions/:subscriptionId";
  // AMF: Event Exposure Service
  static inline const std::string AmfEvtsBase              = "/namf-evts/";
  static inline const std::string AmfEvtsPathSubscriptions = "/subscriptions";
  static inline const std::string AmfEvtsPathSubscriptionsSubscriptionId =
      "/subscriptions/:subscriptionId";
  // AMF: Location Service
  static inline const std::string AmflocBase = "/namf-loc/";
  static inline const std::string AmflocPathUeContextIdProvidePosInfo =
      "/:ueContextId/provide-pos-info";
  static inline const std::string AmflocPathUeContextIdProvideLocInfo =
      "/:ueContextId/provide-loc-info";
  static inline const std::string AmflocPathUeContextIdCancelPosInfo =
      "/:ueContextId/cancel-pos-info";
  static inline const std::string AmflocPathDetermineLocation =
      "/determine-location";
  // TODO: AMF: Mobile Terminated Service
  // AMF Configuration Service
  static inline const std::string AmfConfBase              = "/namf-oai/";
  static inline const std::string AmfConfPathConfiguration = "/configuration/";
  // AMF Status Notify
  static inline const std::string AmfStatusNotifBase = "/namf-status-notify/";
  static inline const std::string AmfStatusNotifPathPduSessionRelease =
      "/pdu-session-release/callback/";
  static inline const std::string
      AmfStatusNotifPathPduSessionReleasePduSessionId =
          "/pdu-session-release/callback/:ueContextId/:pduSessionId";

  // AMF callback for AMF registration for 3GPP access
  static inline const std::string AmfCallbackBase = "/namf-callback/";
  static inline const std::string AmfCallbackPathDeregistrationNotification =
      ":ueId/deregistration-notification";

  // AUSF: UEAuthentication
  static inline const std::string AusfAuthBase = "/nausf-auth/";
  static inline const std::string AusfAuthPathUeAuthentications =
      "/ue-authentications";
  static inline const std::string
      AusfAuthPathUeAuthentications5gAkaConfirmation =
          "/ue-authentications/:authCtxId/5g-aka-confirmation";
  static inline const std::string AusfAuthPathUeAuthenticationsEapSession =
      "/ue-authentications/:authCtxId/eap-session";
  // TODO: AUSF: SoR Protection
  // TODO: AUSF: UPU Protection

  // NRF: NF Management Service
  static inline const std::string NrfNfmBase = "/nnrf-nfm/";
  static inline const std::string NrfNfmPathNfInstancesNfInstanceId =
      "/nf-instances/:nfInstanceID";
  static inline const std::string NrfNfmPathNfInstances   = "/nf-instances";
  static inline const std::string NrfNfmPathSubscriptions = "/subscriptions";
  static inline const std::string NrfNfmPathSubscriptionsSubscriptionId =
      "/subscriptions/:subscriptionID";
  // NRF: NF Discovery Service
  static inline const std::string NrfDiscBase            = "/nnrf-disc/";
  static inline const std::string NrfDiscPathNfInstances = "/nf-instances";
  static inline const std::string NrfDiscPathSearchesSearchId =
      "/searches/:searchId";
  static inline const std::string NrfDiscPathSearchesSearchIdComplete =
      "/searches/:searchId/complete";
  static inline const std::string NrfDiscPathScpDomainRoutingInfo =
      "/scp-domain-routing-info";
  static inline const std::string NrfDiscPathScpDomainRoutingInfoSubs =
      "/scp-domain-routing-info-subs";
  static inline const std::string
      NrfDiscPathScpDomainRoutingInfoSubsSubscriptionId =
          "/scp-domain-routing-info-subs/:subscriptionID";
  // TODO: NRF: Access Token Service
  // TODO: NRF: Bootstrapping Service

  // NSSF: Network Slice Selection Service
  static inline const std::string NssfNsSelectionBase = "/nnssf-nsselection/";
  static inline const std::string NssfNsSelectionPathNetworSliceInformation =
      "/network-slice-information";
  static inline const std::string
      NssfNsSelectionParametersSliceInfoRequestForRegistration =
          "slice-info-request-for-registration";
  static inline const std::string
      NssfNsSelectionParametersSliceInfoRequestForPduSession =
          "slice-info-request-for-pdu-session";

  // NSSF: NSSAI Availability Service
  static inline const std::string NssfNssaiAvailabilityBase =
      "/nnssf-nssaiavailability/";
  static inline const std::string NssfNssaiAvailabilityPathNfInstanceId =
      "/nssai-availability/:nfId";
  static inline const std::string NssfNssaiAvailabilityPathSubscriptions =
      "/nssai-availability/subscriptions";
  static inline const std::string NssfNssaiAvailabilityPathSubscriptionId =
      "/nssai-availability/subscriptions/:subscriptionId";
  static inline const std::string NssfNssaiAvailabilityPathNssaiAvailability =
      "/nssai-availability";

  // TODO: PCF

  // SMF: SMF PDU Session Service
  static inline const std::string SmfPduSessionBase = "/nsmf-pdusession/";
  static inline const std::string SmfPduSessionPathSmContexts = "/sm-contexts";
  static inline const std::string SmfPduSessionPathSmContextsCreate =
      "/sm-contexts/:smContextRef";
  static inline const std::string SmfPduSessionPathSmContextsRetrieve =
      "/sm-contexts/:smContextRef/retrieve";
  static inline const std::string SmfPduSessionPathSmContextsModify =
      "/sm-contexts/:smContextRef/modify";
  static inline const std::string SmfPduSessionPathSmContextsRelease =
      "/sm-contexts/:smContextRef/release";
  static inline const std::string SmfPduSessionPathSmContextsSendMoData =
      "/sm-contexts/:smContextRef/send-mo-data";
  static inline const std::string SmfPduSessionPathPduSessions =
      "/pdu-sessions";
  static inline const std::string SmfPduSessionPathPduSessionsModify =
      "/pdu-sessions/:pduSessionRef/modify";
  static inline const std::string SmfPduSessionPathPduSessionsRelease =
      "/pdu-sessions/:pduSessionRef/release";
  static inline const std::string SmfPduSessionPathPduSessionsRetrieve =
      "/pdu-sessions/:pduSessionRef/retrieve";
  static inline const std::string SmfPduSessionPathPduSessionsTransferMoData =
      "/pdu-sessions/:pduSessionRef/transfer-mo-data";
  // TODO: SMF: Session Management Event Exposure Service

  // UDM: Subscriber Data Management
  static inline const std::string UdmSdmBase           = "/nudm-sdm/";
  static inline const std::string UdmSdmPathSupi       = "/:supi";
  static inline const std::string UdmSdmPathSupiNssai  = "/:supi/nssai";
  static inline const std::string UdmSdmPathSupiAmData = "/:supi/am-data";
  static inline const std::string UdmSdmPathSupiSmfSelData =
      "/:supi/smf-select-data";
  static inline const std::string UdmSdmPathSupiUeCtxInSmfData =
      "/:supi/ue-context-in-smf-data";
  static inline const std::string UdmSdmPathSupiUeCtxInSmsfData =
      "/:supi/ue-context-in-smsf-data";
  static inline const std::string UdmSdmPathSupiTraceConfigData =
      "/:supi/trace-data";
  static inline const std::string UdmSdmPathSupiSmData  = "/:supi/sm-data";
  static inline const std::string UdmSdmPathSupiSmsData = "/:supi/sms-data";
  static inline const std::string UdmSdmPathSupiSmsMngtData =
      "/:supi/sms-mng-data";
  static inline const std::string UdmSdmPathSupiSdmSubscriptions =
      "/:supi/sdm-subscriptions";
  static inline const std::string UdmSdmPathSupiSdmSubscriptionsSubscriptionId =
      "/:supi/sdm-subscriptions/:subscriptionId";
  static inline const std::string UdmSdmPathUeIdSupiOrGpsi =
      "/:gpsi/id-translation-result";
  static inline const std::string UdmSdmPathSupiAmDataSorAckInfo =
      "/:supi/am-data/sor-ack";
  static inline const std::string UdmSdmPathSupiAmDataUpuAck =
      "/:supi/am-data/upu-ack";
  static inline const std::string UdmSdmPathSupiAmDataSubscribedSNssaisAck =
      "/:supi/am-data/subscribed-snssais-ack";
  static inline const std::string UdmSdmPathSupiAmDataCagAck =
      "/:supi/am-data/cag-ack";
  static inline const std::string UdmSdmPathSharedData = "/shared-data";
  static inline const std::string UdmSdmPathSharedDataSubscriptions =
      "/shared-data-subscriptions";
  static inline const std::string
      UdmSdmPathSharedDataSubscriptionsSubscriptionId =
          "/shared-data-subscriptions/:subscriptionId";
  static inline const std::string UdmSdmPathGroupDataGroupIdentifiers =
      "/group-data/group-identifiers";
  // UDM: UE Authentication Service
  static inline const std::string UdmUeAuBase = "/nudm-ueau/";
  static inline const std::string UdmUeAuPathGenerateAuthData =
      "/:supiOrSuci/security-information/generate-auth-data";
  static inline const std::string UdmUeAuPathRgAuthData =
      "/:supiOrSuci/security-information-rg";
  static inline const std::string UdmUeAuPathConfirmAuth = "/:supi/auth-events";
  static inline const std::string UdmUeAuPathGenerateHssAuthenticationVectors =
      "/:supi/hss-security-information/:hssAuthType/generate-av";
  static inline const std::string UdmUeAuPathAuthEventId =
      "/:supi/auth-events/:authEventId";

  // UDM UE Context Management Service
  static inline const std::string UdmUeCmBase = "/nudm-uecm/";
  static inline const std::string UdmUeCmPathRegistrations =
      "/:ueId/registrations";
  static inline const std::string UdmUeCmPath3gppRegistrations =
      "/:ueId/registrations/amf-3gpp-access";
  static inline const std::string UdmUeCmPathDeregAmf =
      "/:ueId/registrations/amf-3gpp-access/dereg-amf";
  static inline const std::string UdmUeCmPathPeiUpdate =
      "/:ueId/registrations/amf-3gpp-access/pei-update";
  static inline const std::string UdmUeCmPathNon3GppRegistration =
      "/:ueId/registrations/amf-non-3gpp-access";
  static inline const std::string UdmUeCmPathSmfRegistration =
      "/:ueId/registrations/smf-registrations";
  static inline const std::string UdmUeCmPathSmfRegistrationPduSession =
      "/:ueId/registrations/smf-registrations/:pduSessionId";
  static inline const std::string UdmUeCmPath3GppSmsfRegistration =
      "/:ueId/registrations/smsf-3gpp-access";
  static inline const std::string UdmUeCmPathNon3GppSmsfRegistration =
      "/:ueId/registrations/smsf-non-3gpp-access";
  static inline const std::string UdmUeCmPathIpSmGwRegistration =
      "/:ueId/registrations/ip-sm-gw";
  static inline const std::string UdmUeCmPathRestorePcscf = "/restore-pcscf";
  static inline const std::string UdmUeCmPathLocationInfo =
      "/:ueId/registrations/location";

  // UDM Event Exposure Service
  static inline const std::string UdmEeBase = "/nudm-ee/";
  static inline const std::string UdmEePathEeSubscription =
      "/:ueIdentity/ee-subscriptions";
  static inline const std::string UdmEePathEeSubscriptionSubscriptionId =
      "/:ueIdentity/ee-subscriptions/:subscriptionId";
  // TODO: UDM Parameter Provision Service
  // TODO: UDM NIDD Authorization

  // UDR: Data Repository Service
  static inline const std::string UdrDataRepositoryBase = "/nudr-dr/";
  static inline const std::string
      UdrDrPathSubscriptionDataAuthenticationSubscription =
          "/subscription-data/:ueId/authentication-data/"
          "authentication-subscription";
  static inline const std::string
      UdrDrPathSubscriptionDataAuthenticationStatus =
          "/subscription-data/:ueId/authentication-data/authentication-status";
  static inline const std::string
      UdrDrPathSubscriptionDataAuthenticationStatusServingNetworkName =
          "/subscription-data/:ueId/authentication-data/authentication-status/"
          ":servingNetworkName";
  static inline const std::string
      UdrDrPathSubscriptionDataUeUpdateConfirmationDataSorData =
          "/subscription-data/:ueId/ue-update-confirmation-data/sor-data";
  static inline const std::string
      UdrDrPathSubscriptionDataUeUpdateConfirmationDataUpuData =
          "/subscription-data/:ueId/ue-update-confirmation-data/upu-data";
  static inline const std::string
      UdrDrPathSubscriptionDataUeUpdateConfirmationSubscribedCag =
          "/subscription-data/:ueId/ue-update-confirmation-data/subscribed-cag";
  static inline const std::string
      UdrDrPathSubscriptionDataUeUpdateConfirmationSubscribedSnssais =
          "/subscription-data/:ueId/ue-update-confirmation-data/"
          "subscribed-snssais";
  static inline const std::string UdrDrPathSubscriptionDataProvisionedData =
      "/subscription-data/:ueId/:servingPlmnId/provisioned-data";
  static inline const std::string
      UdrDrPathSubscriptionDataProvisionedDataAmData =
          "/subscription-data/:ueId/:servingPlmnId/provisioned-data/am-data";
  static inline const std::string UdrDrPathSubscriptionDataProvisionedDataSmf =
      "/subscription-data/:ueId/:servingPlmnId/provisioned-data/"
      "smf-selection-subscription-data";
  static inline const std::string
      UdrDrPathSubscriptionDataProvisionedDataSmData =
          "/subscription-data/:ueId/:servingPlmnId/provisioned-data/sm-data";
  static inline const std::string
      UdrDrPathAllSubscriptionDataProvisionedDataSmData =
          "/subscription-data/provisioned-data/sm-data";
  static inline const std::string
      UdrDrPathSubscriptionDataProvisionedDataLcsBcaData =
          "/subscription-data/:ueId/:servingPlmnId/provisioned-data/"
          "lcs-bca-data";
  static inline const std::string UdrDrPathSubscriptionDataContextData =
      "/subscription-data/:ueId/context-data";
  static inline const std::string
      UdrDrPathSubscriptionDataContextDataAmf3gppAccess =
          "/subscription-data/:ueId/context-data/amf-3gpp-access";
  static inline const std::string
      UdrDrPathSubscriptionDataContextDataAmfNon3gppAccess =
          "/subscription-data/:ueId/context-data/amf-non-3gpp-access";
  static inline const std::string
      UdrDrPathSubscriptionDataContextDataSmfRegistrations =
          "/subscription-data/:ueId/context-data/smf-registrations";
  static inline const std::string
      UdrDrPathSubscriptionDataContextDataSmfRegistrationsPduSession =
          "/subscription-data/:ueId/context-data/smf-registrations/"
          ":pduSessionId";
  static inline const std::string
      UdrDrPathSubscriptionDataOperatorSpecificData =
          "/subscription-data/:ueId/operator-specific-data";
  static inline const std::string
      UdrDrPathSubscriptionDataContextDataSmsf3gppAccess =
          "/subscription-data/:ueId/context-data/smsf-3gpp-access";
  static inline const std::string
      UdrDrPathSubscriptionDataContextDataSmsfNon3gppAccess =
          "/subscription-data/:ueId/context-data/smsf-non-3gpp-access";
  static inline const std::string UdrDrPathSubscriptionDataContextDataLocation =
      "/subscription-data/:ueId/context-data/location";
  static inline const std::string UdrDrPathSubscriptionDataContextDataIpSmGw =
      "/subscription-data/:ueId/context-data/ip-sm-gw";
  static inline const std::string UdrDrPathSubscriptionDataContextDataMwd =
      "/subscription-data/:ueId/context-data/mwd";
  static inline const std::string
      UdrDrPathSubscriptionDataProvisionedDataSmsMngData =
          "/subscription-data/:ueId/:servingPlmnId/provisioned-data/"
          "sms-mng-data";
  static inline const std::string
      UdrDrPathSubscriptionDataProvisionedDataSmsData =
          "/subscription-data/:ueId/:servingPlmnId/provisioned-data/sms-data";
  static inline const std::string UdrDrPathSubscriptionDataLcsPrivacyData =
      "/subscription-data/:ueId/lcs-privacy-data";
  static inline const std::string UdrDrPathSubscriptionDataLcsMoData =
      "/subscription-data/:ueId/lcs-mo-data";
  static inline const std::string UdrDrPathSubscriptionDataPpData =
      "/subscription-data/:ueId/pp-data";
  static inline const std::string
      UdrDrPathSubscriptionDataContextDataEeSubscriptions =
          "/subscription-data/:ueId/context-data/ee-subscriptions";
  static inline const std::string
      UdrDrPathSubscriptionDataContextDataEeSubscriptionsSubsId =
          "/subscription-data/:ueId/context-data/ee-subscriptions/:subsId";
  static inline const std::string
      UdrDrPathSubscriptionDataContextDataEeSubscriptionsSubsIdAmf =
          "/subscription-data/:ueId/context-data/ee-subscriptions/:subsId/"
          "amf-subscriptions";
  static inline const std::string
      UdrDrPathSubscriptionDataContextDataEeSubscriptionsSubsIdSmf =
          "/subscription-data/:ueId/context-data/ee-subscriptions/:subsId/"
          "smf-subscriptions";
  static inline const std::string
      UdrDrPathSubscriptionDataContextDataEeSubscriptionsSubsIdHss =
          "/subscription-data/:ueId/context-data/ee-subscriptions/:subsId/"
          "hss-subscriptions";
  static inline const std::string
      UdrDrPathSubscriptionDataGroupDataEeSubscriptions =
          "/subscription-data/group-data/:ueGroupId/ee-subscriptions";
  static inline const std::string
      UdrDrPathSubscriptionDataGroupDataEeSubscriptionsSubsId =
          "/subscription-data/group-data/:ueGroupId/ee-subscriptions/:subsId";
  static inline const std::string
      UdrDrPathSubscriptionDataGroupDataEeProfileData =
          "/subscription-data/group-data/:ueGroupId/ee-profile-data";
  static inline const std::string UdrDrPathSubscriptionDataGroupData5gVnGroups =
      "/subscription-data/group-data/5g-vn-groups";
  static inline const std::string
      UdrDrPathSubscriptionDataGroupData5gVnGroupsExternalGroupId =
          "/subscription-data/group-data/5g-vn-groups/:externalGroupId";
  static inline const std::string
      UdrDrPathSubscriptionDataGroupData5gVnGroupsInternal =
          "/subscription-data/group-data/5g-vn-groups/internal";
  static inline const std::string
      UdrDrPathSubscriptionDataGroupData5gVnGroupsPpProfileData =
          "/subscription-data/group-data/5g-vn-groups/pp-profile-data";
  static inline const std::string UdrDrPathSubscriptionDataEeProfileData =
      "/subscription-data/:ueId/ee-profile-data";
  static inline const std::string
      UdrDrPathSubscriptionDataContextDataSdmSubscriptions =
          "/subscription-data/:ueId/context-data/sdm-subscriptions";
  static inline const std::string
      UdrDrPathSubscriptionDataContextDataSdmSubscriptionsSubsId =
          "/subscription-data/:ueId/context-data/sdm-subscriptions/:subsId";
  static inline const std::string
      UdrDrPathSubscriptionDataContextDataSdmSubscriptionsSubsIdHss =
          "/subscription-data/:ueId/context-data/sdm-subscriptions/:subsId/"
          "hss-sdm-subscriptions";
  static inline const std::string UdrDrPathSubscriptionDataSharedData =
      "/subscription-data/shared-data";
  static inline const std::string
      UdrDrPathSubscriptionDataSharedDataSharedDataId =
          "/subscription-data/shared-data/:sharedDataId";
  static inline const std::string UdrDrPathSubscriptionDataSubsToNotify =
      "/subscription-data/subs-to-notify";
  static inline const std::string UdrDrPathSubscriptionDataSubsToNotifySubsId =
      "/subscription-data/subs-to-notify/:subsId";
  static inline const std::string
      UdrDrPathSubscriptionDataProvisionedDataTraceData =
          "/subscription-data/:ueId/:servingPlmnId/provisioned-data/trace-data";
  static inline const std::string UdrDrPathSubscriptionDataIdentityData =
      "/subscription-data/:ueId/identity-data";
  static inline const std::string
      UdrDrPathSubscriptionDataOperatorDeterminedBarringData =
          "/subscription-data/:ueId/operator-determined-barring-data";
  static inline const std::string
      UdrDrPathSubscriptionDataNiddAuthorizationData =
          "/subscription-data/:ueId/nidd-authorization-data";
  static inline const std::string UdrDrPathSubscriptionDataV2xData =
      "/subscription-data/:ueId/v2x-data";
  static inline const std::string UdrDrPathSubscriptionDataPpProfileData =
      "/subscription-data/:ueId/pp-profile-data";
  static inline const std::string
      UdrDrPathSubscriptionDataCoverageRestrictionData =
          "/subscription-data/:ueId/coverage-restriction-data";
  static inline const std::string
      UdrDrPathSubscriptionDataGroupDataGroupIdentifier =
          "/subscription-data/group-data/group-identifiers";
  static inline const std::string UdrDrPathSubscriptionDataUesAmData =
      "/policy-data/ues/:ueId/am-data";
  static inline const std::string UdrDrPathSubscriptionDataUesUePolicySet =
      "/policy-data/ues/:ueId/ue-policy-set";
  static inline const std::string UdrDrPathSubscriptionDataUesSmData =
      "/policy-data/ues/:ueId/sm-data";
  static inline const std::string UdrDrPathSubscriptionDataUesSmDataUsageMonId =
      "/policy-data/ues/:ueId/sm-data/:usageMonId";
  static inline const std::string
      UdrDrPathSubscriptionDataSponsorConnectivityDataSponsorId =
          "/policy-data/sponsor-connectivity-data/:sponsorId";
  static inline const std::string UdrDrPathSubscriptionDataPolicyDataBdtData =
      "/policy-data/bdt-data";
  static inline const std::string
      UdrDrPathSubscriptionDataPolicyDataBdtDataBdtReferenceId =
          "/policy-data/bdt-data/:bdtReferenceId";
  static inline const std::string
      UdrDrPathSubscriptionDataPolicyDataSubsToNotify =
          "/policy-data/subs-to-notify";
  static inline const std::string
      UdrDrPathSubscriptionDataPolicyDataSubsToNotitySubsId =
          "/policy-data/subs-to-notify/:subsId";
  static inline const std::string
      UdrDrPathSubscriptionDataPolicyDataUesOperatorSpecificData =
          "/policy-data/ues/:ueId/operator-specific-data";
  static inline const std::string UdrDrPathApplicationDataPfds =
      "/application-data/pfds";
  static inline const std::string UdrDrPathApplicationDataPfdsApp =
      "/application-data/pfds/:appId";
  static inline const std::string UdrDrPathApplicationDataInfluenceData =
      "/application-data/influenceData";
  static inline const std::string
      UdrDrPathApplicationDataInfluenceDataInfluenceId =
          "/application-data/influenceData/:influenceId";
  static inline const std::string UdrDrPathApplicationDataPlmnsUePolicySet =
      "/policy-data/plmns/:plmnId/ue-policy-set";
  static inline const std::string UdrDrPathApplicationDataBdtPolicyData =
      "/application-data/bdtPolicyData";
  static inline const std::string
      UdrDrPathApplicationDataBdtPolicyDataBdtPolicyId =
          "/application-data/bdtPolicyData/:bdtPolicyId";
  static inline const std::string UdrDrPathApplicationDataIptvConfigData =
      "/application-data/iptvConfigData";
  static inline const std::string
      UdrDrPathApplicationDataIptvConfigDataConfigurationId =
          "/application-data/iptvConfigData/:configurationId";
  static inline const std::string
      UdrDrPathApplicationDataInfluenceDataSubsToNotify =
          "/application-data/influenceData/subs-to-notify";
  static inline const std::string
      UdrDrPathApplicationDataInfluenceDataSubsToNotifySubscriptionId =
          "/application-data/influenceData/subs-to-notify/:subscriptionId";
  static inline const std::string UdrDrPathApplicationDataServiceParamData =
      "/application-data/serviceParamData";
  static inline const std::string
      UdrDrPathApplicationDataServiceParamDataServiceParamId =
          "/application-data/serviceParamData/:serviceParamId";
  static inline const std::string UdrDrPathApplicationDataSubsToNotify =
      "/application-data/subs-to-notify";
  static inline const std::string UdrDrPathApplicationDataSubsToNotifySubsId =
      "/application-data/subs-to-notify/:subsId";
  static inline const std::string UdrDrPathExposureDataAccessAndMobilityData =
      "/exposure-data/:ueId/access-and-mobility-data";
  static inline const std::string
      UdrDrPathExposureDataSessionManagementDataPduSessionId =
          "/exposure-data/:ueId/session-management-data/:pduSessionId";
  static inline const std::string UdrDrPathExposureDataSubsToNotify =
      "/exposure-data/subs-to-notify";
  static inline const std::string UdrDrPathExposureDataSubsToNotifySubsId =
      "/exposure-data/subs-to-notify/:subId";

  // UDR: Configuration
  static inline const std::string UdrConfBase              = "/nudr-oai/";
  static inline const std::string UdrConfPathConfiguration = "/configuration/";

  // UDSF: Data Repository
  static inline const std::string UdsfDrBase = "/nudsf-dr/";
  static inline const std::string UdsfDrBlockCRUDApi =
      ":realmId/:storageId/records/:recordId/blocks/:blockId";
  static inline const std::string UdsfDrBlockCRUDApiList =
      ":realmId/:storageId/records/:recordId/blocks";
  static inline const std::string UdsfDrMetaSchemaCRUDApi =
      "/:realmId/:storageId/meta-schemas/:schemaId";
  static inline const std::string UdsfDrNotificationSubscriptionCRUDApi =
      "/:realmId/:storageId/subs-to-notify/:subscriptionId";
  static inline const std::string UdsfDrNotificationSubscriptionsCRUDApi =
      "/:realmId/:storageId/subs-to-notify";
  static inline const std::string UdsfDrRecordCRUDApi =
      "/:realmId/:storageId/records/:recordId";
  static inline const std::string UdsfDrRecordCRUDApiList =
      "/:realmId/:storageId/records";
  static inline const std::string UdsfDrRecordCRUDApiMeta =
      "/:realmId/:storageId/records/:recordId/meta";

  // TODO: UDSF Timer

  // LMF: LMF Location Service
  static inline const std::string LmfLocBase = "/nlmf-loc/";
  static inline const std::string LmfLocDetermineLocation =
      "/determine-location";
  static inline const std::string LmfLocCancelLocation = "/cancel-location";
  static inline const std::string LmfLocLocationContextTransfer =
      "/location-context-transfer";

  // LMF: LMF Notify
  static inline const std::string LmfN2InfoNotifyBase = "/nlmf-n2info-notify/";
  static inline const std::string LmfN2InfoNotifyNrppaCallback =
      "/nrppa/callback/";
  static inline const std::string LmfN2InfoNotifyNrppaCallbackUeContextId =
      "/nrppa/callback/:ueContextId";
  static inline const std::string LmfNonUeN2InfoNotifyBase =
      "/nlmf-non-ue-n2info-notify/";
  static inline const std::string LmfNonUeN2InfoNotifyNrppaCallback =
      "/nrppa/callback/";

  /*
   * Get NRF Nfm API Root
   * @param [const nf_addr_t& ] nrf_addr: NRF's Addr info
   * @param [std::string& ] api_root: NRF's API Root
   * @return void
   */
  static void get_nrf_nfm_api_root(
      const nf_addr_t& nrf_addr, std::string& api_root);

  /*
   * Get NRF NF Register URI
   * @param [const nf_addr_t& ] nrf_addr: NRF's Addr info
   * @param [const std::string& ] nf_instance: NF instance Id
   * @param [std::string& ] uri: NRF NF Register URI
   * @return void
   */
  static void get_nrf_nf_instance_uri(
      const nf_addr_t& nrf_addr, const std::string& nf_instance,
      std::string& uri);

  /*
   * Get NRF Disc API Root
   * @param [const nf_addr_t& ] nrf_addr: NRF's Addr info
   * @param [std::string& ] api_root: NRF Discovery API Root
   * @return void
   */
  static void get_nrf_disc_api_root(
      const nf_addr_t& nrf_addr, std::string& api_root);

  /*
   * Get NRF NF Discovery SearchNFInstances URI
   * @param [const nf_addr_t& ] nrf_addr: NRF's Addr info
   * @param [std::string& ] uri: NRF SearchNFInstances URI
   * @return void
   */
  static void get_nrf_disc_search_nf_instances_uri(
      const nf_addr_t& nrf_addr, std::string& uri);

  /*
   * Get FMT format from an input string (3GPP format)
   * @param [const std::string& ] input_str: Input string
   * @param [std::string& ] output_str: Output string
   * @return void
   */
  static void get_fmt_format_form(
      const std::string& input_str, std::string& output_str);
};
}  // namespace oai::common::sbi
