/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_UDM_APP_HPP_SEEN
#define FILE_UDM_APP_HPP_SEEN

#include <map>
#include <shared_mutex>
#include <string>

#include "Amf3GppAccessRegistration.h"
#include "AuthEvent.h"
#include "AuthenticationInfoRequest.h"
#include "CreatedEeSubscription.h"
#include "EeSubscription.h"
#include "PatchItem.h"
#include "PlmnId.h"
#include "ProblemDetails.h"
#include "SdmSubscription.h"
#include "Snssai.h"
#include "udm.h"
#include "udm_event.hpp"
#include "uint_generator.hpp"

namespace oai::udm::app {

class udm_app {
 public:
  explicit udm_app(const std::string& config_file, udm_event& ev);
  udm_app(udm_app const&) = delete;
  void operator=(udm_app const&) = delete;
  virtual ~udm_app();

  bool start();
  void stop();

  /*
   * Handle a request to generate the authentication data
   * @param [const std::string&] supiOrSuci: UE's SUPI/SUCI
   * @param [const oai::model::udm::AuthenticationInfoRequest&]
   * authenticationInfoRequest: request's info
   * @param [nlohmann::json&] auth_info_response: Authentication response's info
   * @param [uint32_t&] code: response's code
   * @return void
   */
  void handle_generate_auth_data_request(
      const std::string& supiOrSuci,
      const oai::model::udm::AuthenticationInfoRequest&
          authenticationInfoRequest,
      nlohmann::json& auth_info_response, uint32_t& code);

  /*
   * Handle a request to confirm the authentication data
   * @param [const std::string&] supi: UE's SUPI
   * @param [const oai::model::udm::AuthEvent&] authEvent: Authentication Event
   * @param [nlohmann::json&] confirm_response: Confirm response
   * @param [std::string&] location: location of the resource
   * @param [uint32_t&] code: response's code
   * @return void
   */
  void handle_confirm_auth(
      const std::string& supi, const oai::model::udm::AuthEvent& authEvent,
      nlohmann::json& confirm_response, std::string& location, uint32_t& code);

  /*
   * Handle a request to delete an authentication data
   * @param [const std::string&] supi: UE's SUPI
   * @param [const std::string&] authEventId: Event ID
   * @param [const oai::model::udm::AuthEvent&] authEvent: Authentication Event
   * @param [nlohmann::json&] auth_response: Authentication response
   * @param [uint32_t&] code: response's code
   * @return void
   */
  void handle_delete_auth(
      const std::string& supi, const std::string& authEventId,
      const oai::model::udm::AuthEvent& authEvent,
      nlohmann::json& auth_response, uint32_t& code);

  /*
   * Handle a request to get the Access and Mobility Subscription Data
   * @param [const std::string&] supi: UE's SUPI
   * @param [nlohmann::json&] response_data: response's info
   * @param [uint32_t&] code: response's code
   * @param [oai::model::common::PlmnId] PlmnId: PLMN ID
   * @return void
   */
  void handle_access_mobility_subscription_data_retrieval(
      const std::string& supi, nlohmann::json& response_data, uint32_t& code,
      oai::model::common::PlmnId PlmnId = {});

  /*
   * Handle a request to Create an AMF Registration for 3GPP Access info
   * @param [const std::string&] supi: UE's SUPI
   * @param [const oai::model::udm::Amf3GppAccessRegistration&]
   * amf_3gpp_access_registration: Registration info
   * @param [nlohmann::json&] response_data: response's info
   * @param [uint32_t&] code: response's code
   * @param [oai::model::common::PlmnId] PlmnId: PLMN ID
   * @return void
   */
  void handle_amf_registration_for_3gpp_access(
      const std::string& ue_id,
      const oai::model::udm::Amf3GppAccessRegistration&
          amf_3gpp_access_registration,
      nlohmann::json& response_data, uint32_t& code);

  /*
   * Handle a request to get the Session Management Subscription Data
   * @param [const std::string&] supi: UE's SUPI
   * @param [nlohmann::json&] response_data: response's info
   * @param [uint32_t&] code: response's code
   * @param [oai::model::common::Snssai] snssai: SNSSAI
   * @param [oai::model::common::PlmnId] PlmnId: PLMN ID
   * @param [std::string&] dnn: DNN
   * @return void
   */
  void handle_session_management_subscription_data_retrieval(
      const std::string& supi, nlohmann::json& response_data, uint32_t& code,
      oai::model::common::Snssai snssai = {}, std::string dnn = {},
      oai::model::common::PlmnId plmn_id = {});

  /*
   * Handle a request to get the Slice Selection Subscription Data
   * @param [const std::string&] supi: UE's SUPI
   * @param [nlohmann::json&] response_data: response's info
   * @param [uint32_t&] code: response's code
   * @param [oai::model::common::PlmnId] PlmnId: PLMN ID
   * @return void
   */
  void handle_slice_selection_subscription_data_retrieval(
      const std::string& supi, nlohmann::json& response_data, uint32_t& code,
      std::string supported_features     = {},
      oai::model::common::PlmnId plmn_id = {});

  /*
   * Handle a request to get the SMF Selection Subscription Data
   * @param [const std::string&] supi: UE's SUPI
   * @param [nlohmann::json&] response_data: response's info
   * @param [uint32_t&] code: response's code
   * @param [std::string] supported_features: supported features
   * @param [oai::model::common::PlmnId] PlmnId: PLMN ID
   * @return void
   */
  void handle_smf_selection_subscription_data_retrieval(
      const std::string& supi, nlohmann::json& response_data, uint32_t& code,
      std::string supported_features     = {},
      oai::model::common::PlmnId plmn_id = {});

  /*
   * Handle a request to create a subscription
   * @param [const std::string&] supi: UE's SUPI
   * @param [const oai::model::udm::SdmSubscription&] sdmSubscription:
   * Suscription info
   * @param [nlohmann::json&] response_data: response's info
   * @param [uint32_t&] code: response's code
   * @return void
   */
  void handle_subscription_creation(
      const std::string& supi,
      const oai::model::udm::SdmSubscription& sdmSubscription,
      nlohmann::json& response_data, uint32_t& code);

  /*
   * Handle a request to create an event subscription
   * @param [const std::string&] supi: UE's SUPI
   * @param [const oai::model::udm::EeSubscription&] eeSubscription: suscription
   * info
   * @param [const oai::model::udm::CreatedEeSubscription&] createdSub: created
   * suscription info
   * @param [uint32_t&] code: response's code
   * @return subscription Id
   */
  evsub_id_t handle_create_ee_subscription(
      const std::string& ueIdentity,
      const oai::model::udm::EeSubscription& eeSubscription,
      oai::model::udm::CreatedEeSubscription& createdSub, uint32_t& code);

  /*
   * Handle a request to delete an event subscription
   * @param [const std::string&] ueIdentity: UE's identity
   * @param [const std::string&] subscriptionId: subscription's Id
   * @param [oai::model::common::ProblemDetails&] problemDetails: problem
   * happened (if exist) when deleting the even
   * @param [uint32_t&] code: response's code
   * @return void
   */
  void handle_delete_ee_subscription(
      const std::string& ueIdentity, const std::string& subscriptionId,
      oai::model::common::ProblemDetails& problemDetails, uint32_t& code);

  /*
   * Handle a request to update an event subscription
   * @param [const std::string&] ueIdentity: UE's identity
   * @param [const std::string&] subscriptionId: subscription's Id
   * @param [const std::vector<oai::model::common::PatchItem>&] patchItem: list
   * of actions
   * @param [oai::model::common::ProblemDetails&] problemDetails: problem
   * happened (if exist) when executing the requests
   * @param [uint32_t&] code: response's code
   * @return void
   */
  void handle_update_ee_subscription(
      const std::string& ueIdentity, const std::string& subscriptionId,
      const std::vector<oai::model::common::PatchItem>& patchItem,
      oai::model::common::ProblemDetails& problemDetails, uint32_t& code);

  /*
   * Generate an unique ID for the new subscription
   * @return the generated ID
   */
  evsub_id_t generate_ev_subscription_id();

  /*
   * Add an Event Subscription to the list
   * @param [const evsub_id_t&] sub_id: Subscription ID
   * @param [std::string] ue_id: UE's identity
   * @param [std::shared_ptr<oai::model::udm::CreatedEeSubscription>] ces: a
   * shared pointer stored information of the created subscription
   * @return void
   */
  void add_event_subscription(
      const evsub_id_t& sub_id, const std::string& ue_id,
      std::shared_ptr<oai::model::udm::CreatedEeSubscription>& ces);

  /*
   * Delete an Event Subscription
   * @param [const std::string&] sub_id: Subscription ID
   * @param [std::string] ue_id: UE's identity
   * @return true if success, otherwise false
   */
  bool delete_event_subscription(
      const std::string& sub_id, const std::string& ue_id);

  /*
   * Update a new item for a subscription
   * @param [const std::string &] path: item name
   * @param [const std::string &] value: new value
   * @return true if success, otherwise false
   */
  bool replace_ee_subscription_item(
      const std::string& path, const std::string& value);

  /*
   * Add a new item for a subscription
   * @param [const std::string &] path: item name
   * @param [const std::string &] value: new value
   * @return true if success, otherwise false
   */
  bool add_ee_subscription_item(
      const std::string& path, const std::string& value);

  /*
   * Remove an item for a subscription
   * @param [const std::string &] path: item name
   * @return true if success, otherwise false
   */
  bool remove_ee_subscription_item(const std::string& path);

  /*
   * Handle Loss of Connectivity Event
   * @param [const std::string&] ue_id: UE's identity (e.g., SUPI)
   * @param [uint8_t] status: Connectivity status
   * @param [uint8_t] http_version: HTTP version
   * @return void
   */
  void handle_ee_loss_of_connectivity(
      const std::string& ue_id, uint8_t status, uint8_t http_version);

  /*
   * Handle UE Reachability For Data Event
   * @param [const std::string&] ue_id: UE's identity (e.g., SUPI)
   * @param [uint8_t] status: UE Reachability For Data status
   * @param [uint8_t] http_version: HTTP version
   * @return void
   */
  void handle_ee_ue_reachability_for_data(
      const std::string& ue_id, uint8_t status, uint8_t http_version);

  /*
   * Increase the value of SQN with a value of 32
   * @param [const std::string&] c_sqn: Current value in form of string
   * @param [std::string&] n_sqn: New value in form of string
   * @return void
   */
  void increment_sqn(const std::string& c_sqn, std::string& n_sqn);

  /*
   * Set problem details to be returned to the request client
   * @param [uint16_t ] status: Status code
   * @param [uint16_t] cause: cause of the problem
   * @param [const std::detail&] detail: Description of the problem
   * @param [nlohmann::json& ] problem_details: problem details in json format
   * @return void
   */
  void set_problem_details(
      uint16_t status, uint16_t cause, const std::string& detail,
      nlohmann::json& problem_details);

 private:
  oai::utils::uint_generator<uint32_t> evsub_id_generator;
  std::map<evsub_id_t, std::shared_ptr<oai::model::udm::CreatedEeSubscription>>
      udm_event_subscriptions;
  std::map<std::string, std::vector<evsub_id_t>> udm_event_subscriptions_per_ue;
  mutable std::shared_mutex m_mutex_udm_event_subscriptions;

  // for Event Handling
  udm_event& event_sub;
  bs2::connection loss_of_connectivity_connection;
  bs2::connection ue_reachability_for_data_connection;
};
}  // namespace oai::udm::app
#include "udm_config.hpp"

#endif /* FILE_UDM_APP_HPP_SEEN */
