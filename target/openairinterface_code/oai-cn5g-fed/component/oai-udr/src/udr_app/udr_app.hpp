/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_UDR_APP_HPP_SEEN
#define FILE_UDR_APP_HPP_SEEN

#include <mysql/mysql.h>
#include <pistache/http.h>

#include <nlohmann/json.hpp>
#include <string>

#include "Amf3GppAccessRegistration.h"
#include "AuthEvent.h"
#include "AuthenticationSubscription.h"
#include "PatchItem.h"
#include "SdmSubscription.h"
#include "SmfRegistration.h"
#include "database_wrapper.hpp"
#include "udr_event.hpp"

namespace oai {
namespace udr {
namespace app {

class udr_app {
 public:
  explicit udr_app(const std::string& config_file, udr_event& ev);
  udr_app(udr_app const&) = delete;
  void operator=(udr_app const&) = delete;

  virtual ~udr_app();

  bool start();
  void stop();

  /*
   * Handle a query for AccessandMobilitySubscriptionData
   * (AccessAndMobilitySubscriptionDataDocumentApiImpl)
   * @param [const std::string&] ue_id: UE Identity
   * @param [const std::string& ] serving_plmn_id: Serving PLMN ID
   * @param [nlohmann::json&] response_data: Response in Json format
   * @param [uint32_t&] code: HTTP response code
   * @return void
   */
  void handle_query_am_data(
      const std::string& ue_id, const std::string& serving_plmn_id,
      nlohmann::json& response_data, uint32_t& code);

  /*
   * Handle a request to create AMF3GPPAccessRegistration Context
   * (AMF3GPPAccessRegistrationDocumentApiImpl)
   * @param [const std::string&] ue_id: UE Identity
   * @param [Amf3GppAccessRegistration& ] amf3GppAccessRegistration:
   * Amf3GppAccessRegistration
   * @param [nlohmann::json&] response_data: Response in Json format
   * @param [uint32_t&] code: HTTP response code
   * @return void
   */
  void handle_create_amf_context_3gpp(
      const std::string& ue_id,
      oai::udr::model::Amf3GppAccessRegistration& amf3GppAccessRegistration,
      nlohmann::json& response_data, uint32_t& code);

  /*
   * Handle a query for AMF3GPPAccessRegistration
   * (AMF3GPPAccessRegistrationDocumentApiImpl)
   * @param [const std::string&] ue_id: UE Identity
   * @param [nlohmann::json&] response_data: Response in Json format
   * @param [uint32_t&] code: HTTP response code
   * @return void
   */
  void handle_query_amf_context_3gpp(
      const std::string& ue_id, nlohmann::json& response_data, uint32_t& code);

  /*
   * Handle a request to create AuthenticationStatus
   * (AuthenticationStatusDocumentApiImpl)
   * @param [const std::string&] ue_id: UE Identity
   * @param [const AuthEvent& ] authEvent:
   * @param [nlohmann::json&] response_data: Response in Json format
   * @param [uint32_t&] code: HTTP response code
   * @return void
   */
  void handle_create_authentication_status(
      const std::string& ue_id, const oai::udr::model::AuthEvent& authEvent,
      nlohmann::json& response_data, uint32_t& code);

  /*
   * Handle a request to delete AuthenticationStatus
   * (AuthenticationStatusDocumentApiImpl)
   * @param [const std::string&] ue_id: UE Identity
   * @param [nlohmann::json&] response_data: Response in Json format
   * @param [uint32_t&] code: HTTP response code
   * @return void
   */
  void handle_delete_authentication_status(
      const std::string& ue_id, nlohmann::json& response_data, uint32_t& code);

  /*
   * Handle a request to retrieve AuthenticationStatus
   * (AuthenticationStatusDocumentApiImpl)
   * @param [const std::string&] ue_id: UE Identity
   * @param [nlohmann::json&] response_data: Response in Json format
   * @param [uint32_t&] code: HTTP response code
   * @return void
   */
  void handle_query_authentication_status(
      const std::string& ue_id, nlohmann::json& response_data, uint32_t& code);

  /*
   * Handle a request to Create an Authentication Subscription
   * (AuthenticationSubscriptionDocumentApiImpl)
   * @param [const std::string&] ue_id: UE Identity
   * @param [const AuthenticationSubscription&] authentication_subscription:
   * UE's subscription information
   * @param [nlohmann::json&] response_data: Response in Json format
   * @param [uint32_t&] http_code: HTTP response code
   * @return void
   */
  void handle_create_authentication_data(
      const std::string& ue_id,
      const oai::udr::model::AuthenticationSubscription&
          authentication_subscription,
      nlohmann::json& response_data, uint32_t& code);

  /*
   * Handle a request to remove the AuthenticationSubscription
   * (AuthenticationDataDocumentApiImpl)
   * @param [const std::string&] ue_id: UE Identity
   * @param [nlohmann::json&] response_data: Response in Json format
   * @param [uint32_t&] code: HTTP response code
   * @return void
   */
  void handle_delete_authentication_data(
      const std::string& ue_id, nlohmann::json& response_data, uint32_t& code);

  /*
   * Handle a request to modify AuthenticationSubscription
   * (AuthenticationSubscriptionDocumentApiImpl)
   * @param [const std::string&] ue_id: UE Identity
   * @param [const std::vector<PatchItem>&] patchItem: PATCH message
   * @param [nlohmann::json&] response_data: Response in Json format
   * @param [uint32_t&] code: HTTP response code
   * @return void
   */
  void handle_modify_authentication_subscription(
      const std::string& ue_id,
      const std::vector<oai::model::common::PatchItem>& patchItem,
      nlohmann::json& response_data, uint32_t& code);

  /*
   * Handle a request to get AuthenticationSubscription
   * (AuthenticationSubscriptionDocumentApiImpl)
   * @param [const std::string&] ue_id: UE Identity
   * @param [nlohmann::json&] response_data: Response in Json format
   * @param [uint32_t&] code: HTTP response code
   * @return void
   */
  void handle_read_authentication_subscription(
      const std::string& ue_id, nlohmann::json& response_data, uint32_t& code);

  /*
   * Handle a request to retrieve SDMSubscription
   * (SDMSubscriptionDocumentApiImpl)
   * @param [const std::string&] ue_id: UE Identity
   * @param [const std::string&] subs_id: subscription ID
   * @param [nlohmann::json&] response_data: Response in Json format
   * @param [uint32_t&] code: HTTP response code
   * @return void
   */
  void handle_query_sdm_subscription(
      const std::string& ue_id, const std::string& subs_id,
      nlohmann::json& response_data, uint32_t& code);

  /*
   * Handle a request to remove SDMSubscription (SDMSubscriptionDocumentApiImpl)
   * @param [const std::string&] ue_id: UE Identity
   * @param [const std::string&] subs_id: subscription ID
   * @param [nlohmann::json&] response_data: Response in Json format
   * @param [uint32_t&] code: HTTP response code
   * @return void
   */
  void handle_remove_sdm_subscription(
      const std::string& ue_id, const std::string& subs_id,
      nlohmann::json& response_data, uint32_t& code);

  /*
   * Handle a request to update SDMSubscription (SDMSubscriptionDocumentApiImpl)
   * @param [const std::string&] ue_id: UE Identity
   * @param [const std::string&] subs_id: subscription ID
   * @param [SdmSubscription&] sdmSubscription: subscription information
   * @param [nlohmann::json&] response_data: Response in Json format
   * @param [uint32_t&] code: HTTP response code
   * @return void
   */
  void handle_update_sdm_subscription(
      const std::string& ue_id, const std::string& subs_id,
      oai::udr::model::SdmSubscription& sdmSubscription,
      nlohmann::json& response_data, uint32_t& code);

  /*
   * Handle a request to create SDMSubscriptions
   * (SDMSubscriptionDocumentApiImpl)
   * @param [const std::string&] ue_id: UE Identity
   * @param [SdmSubscription&] sdmSubscription: subscription information
   * @param [nlohmann::json&] response_data: Response in Json format
   * @param [uint32_t&] code: HTTP response code
   * @return void
   */
  void handle_create_sdm_subscriptions(
      const std::string& ue_id,
      oai::udr::model::SdmSubscription& sdmSubscription,
      nlohmann::json& response_data, uint32_t& code);

  /*
   * Handle a request to retrieve SDMSubscriptions
   * (SDMSubscriptionDocumentApiImpl)
   * @param [const std::string&] ue_id: UE Identity
   * @param [nlohmann::json&] response_data: Response in Json format
   * @param [uint32_t&] code: HTTP response code
   * @return void
   */
  void handle_query_sdm_subscriptions(
      const std::string& ue_id, nlohmann::json& response_data, uint32_t& code);

  /*
   * Handle a request to retrieve SessionManagementSubscription
   * (SessionManagementSubscriptionDataApiImpl)
   * @param [const std::string&] ue_id: UE Identity
   * @param [const std::string&] serving_plmn_id: Serving PLMN ID
   * @param [nlohmann::json&] response_data: Response in Json format
   * @param [const oai::udr::model::Snssai&] snssai: SNSSAI
   * @param [const std::string&] dnn: DNN
   * @param [uint32_t&] code: HTTP response code
   * @return void
   */
  void handle_query_sm_data(
      const std::string& ue_id, const std::string& serving_plmn_id,
      nlohmann::json& response_data, uint32_t& code,
      const std::optional<oai::model::common::Snssai>& snssai,
      const std::optional<std::string>& dnn);

  /*
   * Handle a request to retrieve all SessionManagementSubscriptions
   * (SessionManagementSubscriptionDataApiImpl)
   * @param [nlohmann::json&] response_data: Response in Json format
   * @param [uint32_t&] code: HTTP response code
   * @return void
   */
  void handle_query_sm_data(nlohmann::json& response_data, uint32_t& code);

  /*
   * Handle a request to delete a SessionManagementSubscription
   * (SessionManagementSubscriptionDataApiImpl)
   * @param [const std::string&] ue_id: UE Identity
   * @param [const std::string&] serving_plmn_id: Serving PLMN ID
   * @param [const oai::udr::model::Snssai&] snssai: SNSSAI
   * @param [nlohmann::json&] response_data: Response in Json format
   * @param [uint32_t&] code: HTTP response code
   * @return void
   */
  void handle_delete_sm_data(
      const std::string& ue_id, const std::string& serving_plmn_id,
      const std::optional<oai::model::common::Snssai>& snssai,
      nlohmann::json& response_data, uint32_t& code);

  /*
   * Handle a request to create a SessionManagementSubscription
   * (SessionManagementSubscriptionDataApiImpl)
   * @param [const std::string&] ue_id: User Id (Imsi/supi)
   * @param [const std::string&] serving_plmn_id: Serving PLMN
   * @param [const oai::udr::model::SessionManagementSubscriptionData&]
   * subscription_data: SM Subscription
   * @param [nlohmann::json&] response_data: Response in Json format
   * @param [uint32_t&] code: HTTP response code
   * @param [uint32_t&] resource_id: Resource ID
   * @return void
   */
  void handle_create_sm_data(
      const std::string& ue_id, const std::string& serving_plmn_id,
      oai::udr::model::SessionManagementSubscriptionData& subscription_data,
      nlohmann::json& response_data, uint32_t& code, uint32_t& resource_id);
  /*
   * Handle a request to update a SessionManagementSubscription
   * (SessionManagementSubscriptionDataApiImpl)
   * @param [const std::string&] ue_id: UE Identity
   * @param [const std::string&] serving_plmn_id: Serving PLMN ID
   * @param [const oai::udr::model::SessionManagementSubscriptionData&]
   * subscriptionData: SM Subscription
   * @param [nlohmann::json&] response_data: Response in Json format
   * @param [uint32_t&] code: HTTP response code
   * @param [uint32_t&] resource_id: Resource ID if new resource is created
   * @return void
   */
  void handle_update_sm_data(
      const std::string& ueId, const std::string& servingPlmnId,
      oai::udr::model::SessionManagementSubscriptionData& subscriptionData,
      nlohmann::json& response_data, uint32_t& code, uint32_t& resource_id);

  /*
   * Handle a request to create SMFRegistration (SMFRegistrationDocumentApiImpl)
   * @param [const std::string&] ue_id: UE Identity
   * @param [const int32_t&] pdu_session_id: PDU Session ID
   * @param [const SmfRegistration&] smfRegistration: SMF registration info
   * @param [nlohmann::json&] response_data: Response in Json format
   * @param [uint32_t&] code: HTTP response code
   * @return void
   */
  void handle_create_smf_context_non_3gpp(
      const std::string& ue_id, const int32_t& pdu_session_id,
      const oai::udr::model::SmfRegistration& smfRegistration,
      nlohmann::json& response_data, uint32_t& code);

  /*
   * Handle a request to delete SMFRegistration (SMFRegistrationDocumentApiImpl)
   * @param [const std::string&] ue_id: UE Identity
   * @param [const int32_t&] pdu_session_id: PDU Session ID
   * @param [nlohmann::json&] response_data: Response in Json format
   * @param [uint32_t&] code: HTTP response code
   * @return void
   */
  void handle_delete_smf_context(
      const std::string& ue_id, const int32_t& pdu_session_id,
      nlohmann::json& response_data, uint32_t& code);

  /*
   * Handle a request to retrieve SMFRegistration
   * (SMFRegistrationDocumentApiImpl)
   * @param [const std::string&] ue_id: UE Identity
   * @param [const int32_t&] pdu_session_id: PDU Session ID
   * @param [nlohmann::json&] response_data: Response in Json format
   * @param [uint32_t&] code: HTTP response code
   * @return void
   */
  void handle_query_smf_registration(
      const std::string& ue_id, const int32_t& pdu_session_id,
      nlohmann::json& response_data, uint32_t& code);

  /*
   * Handle a request to retrieve SMFRegistrationsCollection
   * (SMFRegistrationsCollectionApiImpl)
   * @param [const std::string&] ue_id: UE Identity
   * @param [nlohmann::json&] response_data: Response in Json format
   * @param [uint32_t&] code: HTTP response code
   * @return void
   */
  void handle_query_smf_reg_list(
      const std::string& ue_id, nlohmann::json& response_data, uint32_t& code);

  /*
   * Handle a request to retrieve SMFSelectionSubscription
   * (SMFSelectionSubscriptionDataDocumentApiImpl)
   * @param [const std::string&] ue_id: UE Identity
   * @param [const std::string&] serving_plmn_id: Serving PLMN ID
   * @param [nlohmann::json&] response_data: Response in Json format
   * @param [uint32_t&] code: HTTP response code
   * @return void
   */
  void handle_query_smf_select_data(
      const std::string& ue_id, const std::string& serving_plmn_id,
      nlohmann::json& response_data, uint32_t& code);

  /*
   * Get the current UDR's configuration
   * @param [nlohmann::json&]: config_info: UDR configuration
   * @param [uint32_t&] code: HTTP response code
   * @return true if success, otherwise return false
   */
  bool handle_read_configuration(nlohmann::json& config_info, uint32_t& code);

  /*
   * Update UDR configuration
   * @param [nlohmann::json&]: config_info: new UDR configuration
   * @param [uint32_t&] code: HTTP response code
   * @return true if success, otherwise return false
   */
  bool handle_update_configuration(nlohmann::json& config_info, uint32_t& code);

  bool get_supi(
      const std::string& supi_full_format, std::string& supi,
      std::string& prefix);

 private:
  udr_event& event_sub;
  std::shared_ptr<database_wrapper_abstraction> db_connector;
};
}  // namespace app
}  // namespace udr
}  // namespace oai
#include "udr_config.hpp"

#endif /* FILE_UDR_APP_HPP_SEEN */
