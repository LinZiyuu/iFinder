/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_NEF_APP_HPP_SEEN
#define FILE_NEF_APP_HPP_SEEN

#include <shared_mutex>
#include <string>
#include <optional>

#include "AmfEventNotification.h"
#include "IpAddr.h"
#include "MonitoringEventSubscription.h"
#include "MonitoringReport.h"
#include "NefEventExposureNotif.h"
#include "NefEventExposureSubsc.h"
#include "NsmfEventExposureNotification.h"
#include "PatchItem.h"
#include "ProblemDetails.h"
#include "nef.h"
#include "uint_generator.hpp"

using namespace oai::nef::model;

namespace oai::nef::app {

class nef_config;
class nef_app {
 public:
  explicit nef_app(const std::string& config_file);
  nef_app(nef_app const&) = delete;
  void operator=(nef_app const&) = delete;

  virtual ~nef_app();

  /*
   * Generate an unique ID for the new subscription
   * @param [const std::string &] sub_id: the generated ID
   * @return void
   */
  void generate_ev_subscription_id(std::string& sub_id);

  /*
   * Generate an unique ID for the new subscription
   * @param void
   * @return the generated ID
   */
  evsub_id_t generate_ev_subscription_id();

  /*
   * Handle a request to create a subscription (Event Exposure)
   * @param [std::string &] sub_id: ID of the created subscription
   * @param [const NefEventExposureSubsc &] ev_sub: Requested subscription's
   * information
   * @param [NefEventExposureSubsc &] created_ev_sub: Created subscription's
   * information
   * @param [const uint8_t] http_version: HTTP version
   * @param [int &] http_code: HTTP code used to return to the service consumer
   * @param [ProblemDetails &] problem_details: Store details of the error
   * @return void
   */
  void handle_create_individual_subscription(
      std::string& sub_id, const NefEventExposureSubsc& ev_sub,
      NefEventExposureSubsc& created_ev_sub, const uint8_t http_version,
      int& http_code, ProblemDetails& problem_details);

  /*
   * Handle a request to delete a subscription (Event Exposure)
   * @param [std::string &] sub_id: ID of the created subscription
   * @param [const uint8_t] http_version: HTTP version
   * @param [int &] http_code: HTTP code used to return to the service consumer
   * @param [ProblemDetails &] problem_details: Store details of the error
   * @return void
   */
  void handle_remove_individual_subscription(
      const std::string& sub_id, const uint8_t http_version, int& http_code,
      ProblemDetails& problem_details);

  /*
   * Handle a request to get a subscription information (Event Exposure)
   * @param [std::string &] sub_id: ID of the created subscription
   * @param [nlohmann::json &] ev_sub: Subscription's information
   * @param [const uint8_t] http_version: HTTP version
   * @param [int &] http_code: HTTP code used to return to the service consumer
   * @param [ProblemDetails &] problem_details: Store details of the error
   * @return void
   */
  void handle_get_individual_subscription(
      const std::string& sub_id, nlohmann::json& ev_sub,
      const uint8_t http_version, int& http_code,
      ProblemDetails& problem_details);

  /*
   * Handle a request to update a subscription information (Event Exposure)
   * @param [std::string &] sub_id: ID of the created subscription
   * @param [const NefEventExposureSubsc &] ev_sub: Requested subscription's
   * information
   * @param [nlohmann::json &] updated_ev_sub: Updated subscription's
   * information or problem details (Store details of the error)
   * @param [const uint8_t] http_version: HTTP version
   * @param [int &] http_code: HTTP code used to return to the service consumer
   * @return void
   */
  void handle_update_individual_subscription(
      const std::string& sub_id, const NefEventExposureSubsc& ev_sub,
      nlohmann::json& updated_ev_sub, const uint8_t http_version,
      int& http_code);

  /*
   * Handle a NF event notification (from AMF/SMF/UDM, etc)
   * @param [const NefEventExposureNotif &] eventNotif: Notification data
   * @param [nlohmann::json &] response_data: response data
   * @param [const uint8_t] http_version: HTTP version
   * @param [int &] http_code: HTTP code used to return to the service consumer
   * @return void
   */
  void handle_nf_event_notification(
      const NefEventExposureNotif& eventNotif, nlohmann::json& response_data,
      const uint8_t http_version, int& http_code);

  /*
   * Handle an event notification from AMF
   * @param [const AmfEventNotification &] amfEventNotification: Notification
   * data
   * @param [nlohmann::json &] response_data: response data
   * @param [const uint8_t] http_version: HTTP version
   * @param [int &] http_code: HTTP code used to return to the service consumer
   * @return void
   */
  void handle_amf_event_notification(
      const AmfEventNotification& amfEventNotification,
      nlohmann::json& response_data, const uint8_t http_version,
      int& http_code);

  /*
   * Handle an event notification from SMF
   * @param [const NsmfEventExposureNotification &]
   * smfEventExposureNotification: Notification data
   * @param [nlohmann::json &] response_data: response data
   * @param [const uint8_t] http_version: HTTP version
   * @param [int &] http_code: HTTP code used to return to the service consumer
   * @return void
   */
  void handle_smf_event_notification(
      const NsmfEventExposureNotification& smfEventExposureNotification,
      nlohmann::json& response_data, const uint8_t http_version,
      int& http_code);

  /*
   * Handle an event notification from SMF
   * @param [const std::vector<MonitoringReport>&]
   * eventExposureNotif: Notification data
   * @param [nlohmann::json &] response_data: response data
   * @param [const uint8_t] http_version: HTTP version
   * @param [int &] http_code: HTTP code used to return to the service consumer
   * @return void
   */
  void handle_udm_event_notification(
      const std::vector<MonitoringReport>& eventExposureNotif,
      nlohmann::json& response_data, const uint8_t http_version,
      int& http_code);

  /*
   * Handle a request to create a Monitoring subscription
   * @param [std::string &] consumer_nf_id: ID of the consumer NF (e.g., AF)
   * @param [std::string &] sub_id: ID of the created subscription
   * @param [const MonitoringEventSubscription &] ev_sub: Requested
   * subscription's information
   * @param [MonitoringEventSubscription &] created_ev_sub: Created
   * subscription's information
   * @param [const uint8_t] http_version: HTTP version
   * @param [int &] http_code: HTTP code used to return to the service consumer
   * @param [ProblemDetails &] problem_details: Store details of the error
   * @return void
   */
  void handle_create_monitoring_event_subscription(
      const std::string& consumer_nf_id, std::string& sub_id,
      const MonitoringEventSubscription& ev_sub,
      MonitoringEventSubscription& created_ev_sub, const uint8_t http_version,
      int& http_code, ProblemDetails& problem_details);

  /*
   * Handle a request to fetch all subscription information for a consumer NF
   * (e.g., AF)
   * @param [std::string &] consumer_nf_id: ID of the consumer NF (e.g., AF)
   * @param [const uint8_t] http_version: HTTP version
   * @param [nlohmann::json&] result: the result in Json format
   * @param [int &] http_code: HTTP code used to return to the service consumer
   * @return void
   */
  void handle_fetch_all_monitoring_event_subscriptions(
      const std::string& consumer_nf_id,
      const std::optional<std::vector<oai::nef::model::IpAddr>>& ipAddrs,
      const std::optional<std::string>& ipDomain,
      const std::optional<std::vector<std::string>>& macAddrs,
      const uint8_t http_version, nlohmann::json& result, int& http_code);

  /*
   * Handle a request to delete an existing subscription for a consumer NF
   * (e.g., AF)
   * @param [std::string &] consumer_nf_id: ID of the consumer NF (e.g., AF)
   * @param [std::string &] sub_id: ID of the created subscription
   * @param [const uint8_t] http_version: HTTP version
   * @param [int &] http_code: HTTP code used to return to the service consumer
   * @param [ProblemDetails &] problem_details: Store details of the error
   * @return void
   */
  void handle_delete_ind_monitoring_event_subscription(
      const std::string& consumer_nf_id, const std::string& sub_id,
      const uint8_t http_version, int& http_code,
      ProblemDetails& problem_details);

  /*
   * Handle a request to fetch a subscription for a consumer NF
   * (e.g., AF)
   * @param [std::string &] consumer_nf_id: ID of the consumer NF (e.g., AF)
   * @param [std::string &] sub_id: ID of the created subscription
   * @param [const uint8_t] http_version: HTTP version
   * @param [nlohmann::json&] result: the result in Json format
   * @param [int &] http_code: HTTP code used to return to the service consumer
   * @return void
   */
  void handle_fetch_ind_monitoring_event_subscription(
      const std::string& consumer_nf_id, const std::string& sub_id,
      const uint8_t http_version, nlohmann::json& response_data,
      int& http_code);

  /*
   * Handle a request to modify an existing subscription for a consumer NF
   * (e.g., AF)
   * @param [std::string &] consumer_nf_id: ID of the consumer NF (e.g., AF)
   * @param [std::string &] sub_id: ID of the created subscription
   * @param [const std::vector<PatchItem>&] patchItem: List of updated item
   * @param [const uint8_t] http_version: HTTP version
   * @param [int &] http_code: HTTP code used to return to the service consumer
   * @param [ProblemDetails &] problem_details: Store details of the error
   * @return void
   */
  void handle_modify_ind_monitoring_event_subscription(
      const std::string& consumer_nf_id, const std::string& sub_id,
      const std::vector<PatchItem>& patchItem, const uint8_t http_version,
      int& http_code, ProblemDetails& problem_details);

  /*
   * Handle a request to update an existing subscription for a consumer NF
   * (e.g., AF)
   * @param [std::string &] consumer_nf_id: ID of the consumer NF (e.g., AF)
   * @param [std::string &] sub_id: ID of the created subscription
   * @param [const MonitoringEventSubscription&] ev_sub: Updated subscription
   * information
   * @param [const uint8_t] http_version: HTTP version
   * @param [int &] http_code: HTTP code used to return to the service consumer
   * @param [nlohmann::json&] result: the result in Json format
   * @param [ProblemDetails &] problem_details: Store details of the error
   * @return void
   */
  void handle_update_ind_monitoring_event_subscription(
      const std::string& consumer_nf_id, const std::string& sub_id,
      const MonitoringEventSubscription& ev_sub, const uint8_t http_version,
      nlohmann::json& response_data, int& http_code);

  /*
   * Add a new individual subscription (Event Exposure) to the DB
   * @param [std::string &] sub_id: ID of the created subscription
   * @param [std::shared_ptr<NefEventExposureSubsc> &] ces: Pointer to the
   * created subscription
   * @return true if the subscription is created successfully, otherwise return
   * false
   */
  bool add_ee_subscription(
      const std::string& sub_id, std::shared_ptr<NefEventExposureSubsc>& ces);

  /*
   * Add/Create a subscription (Event Exposure) and store to the DB
   * @param [std::string &] consumer_nf_id: ID of the Consumer NF (e.g., AF)
   * @param [std::string &] sub_id: ID of the created subscription
   * @param [std::string &] nf_resource_location: Location of the created
   * subscription from AMF/SMF/UDM
   * @param [std::shared_ptr<MonitoringEventSubscription>&] ces: Shared pointer
   * to the created Event
   * @return true if the subscription is created/added successfully, otherwise
   * return false
   */
  bool add_ee_subscription(
      const std::string& consumer_nf_id, const std::string& sub_id,
      const std::string& nf_resource_location,
      std::shared_ptr<MonitoringEventSubscription>& ces);

  /*
   * Remove an existing subscription (Event Exposure) from the DB
   * @param [std::string &] sub_id: ID of the created subscription
   * @return true if the subscription is removed successfully, otherwise return
   * false
   */
  bool remove_ee_subscription(const std::string& sub_id);

  /*
   * Get info of an existing subscription (Event Exposure) from the DB
   * @param [std::string &] sub_id: ID of the subscription
   * @param [nlohmann::json &] ev_sub: Store subscription info in JSON format
   * @return true if the subscription is existed, otherwise return
   * false
   */
  bool get_ee_subscription(const std::string& sub_id, nlohmann::json& ev_sub);

  /*
   * Remove an existing monitoring subscription (Event Exposure) from the DB
   * @param [std::string &] consumer_nf_id: ID of the Consumer NF (e.g., AF)
   * @param [std::string &] sub_id: ID of the created subscription
   * @return true if the subscription is removed successfully, otherwise return
   * false
   */
  bool remove_monitoring_ee_subscription(
      const std::string& consumer_nf_id, const std::string& sub_id);

  /*
   * Get info of an existing monitoring subscription (Event Exposure) from the
   * DB
   * @param [std::string &] consumer_nf_id: ID of the Consumer NF (e.g., AF)
   * @param [std::string &] sub_id: ID of the subscription
   * @param [nlohmann::json &] ev_sub: Store subscription info in JSON format
   * @return true if the subscription is existed, otherwise return
   * false
   */
  bool get_monitoring_ee_subscription(
      const std::string& consumer_nf_id, const std::string& sub_id,
      nlohmann::json& ev_sub);

  /*
   * Get info of an existing monitoring subscription (Event Exposure) from the
   * DB
   * @param [const std::string &] consumer_nf_id: ID of the Consumer NF (e.g.,
   * AF)
   * @param [const std::string &] sub_id: ID of the subscription
   * @param [std::shared_ptr<MonitoringEventSubscription>&] mes: Store the
   * pointer to the Event
   * @return true if the subscription is existed, otherwise return false
   */
  bool get_monitoring_ee_subscription(
      const std::string& consumer_nf_id, const std::string& sub_id,
      std::shared_ptr<MonitoringEventSubscription>& mes);

  /*
   * Get info of an existing monitoring subscription (Event Exposure) from the
   * DB
   * @param [const std::string &] consumer_nf_id: ID of the Consumer NF (e.g.,
   * AF)
   * @param [std::set<std::string> &] sub_ids: Set of sub IDs associated with
   * this consumer NF
   * @return true if the subscription is existed, otherwise return
   * false
   */
  bool get_sub_ids(
      const std::string& consumer_nf_id, std::set<std::string>& sub_ids);

  /*
   * Subscribe NF (AMF/SMF/UDM, etc) events
   * @param [const MonitoringEventSubscription&] ev_sub: Subscription
   * information (from AF)
   * @param [std::string &] sub_id: ID of the created subscription
   * @param [std::string &] nf_resource_location: Location of the created
   * subscription (generated by AMF)
   * @param [int&] http_code: HTTP response code from NF
   * @return void
   */
  void subscribe_nf_events(
      const MonitoringEventSubscription& ev_sub, const std::string& sub_id,
      std::string& nf_resource_location, int& http_code);

  /*
   * Subscribe to AMF events
   * @param [std::string &] sub_id: ID of the created subscription (from AF)
   * @param [std::string &] nf_resource_location: Location of the created
   * subscription (generated by AMF)
   * @param [const oai::nef::model::MonitoringType_anyOf::eMonitoringType_anyOf
   * &] event_type: Event type
   * @param [const MonitoringEventSubscription&] ev_sub: Subscription
   * information (from AF)
   * @param [int&] http_code: HTTP response code from AMF
   * @return void
   */
  void subscribe_amf_events(
      const std::string& sub_id, std::string& nf_resource_location,
      const oai::nef::model::MonitoringType_anyOf::eMonitoringType_anyOf&
          event_type,
      const MonitoringEventSubscription& ev_sub, int& http_code);

  /*
   * Subscribe to SMF events
   * @param [std::string &] sub_id: ID of the created subscription (from AF)
   * @param [std::string &] nf_resource_location: Location of the created
   * subscription (generated by SMF)
   * @param [const oai::nef::model::MonitoringType_anyOf::eMonitoringType_anyOf
   * &] event_type: Event type
   * @param [const MonitoringEventSubscription&] ev_sub: Subscription
   * information (from AF)
   * @param [int&] http_code: HTTP response code from SMF
   * @return void
   */
  void subscribe_smf_events(
      const std::string& sub_id, std::string& nf_resource_location,
      const oai::nef::model::MonitoringType_anyOf::eMonitoringType_anyOf&
          event_type,
      const MonitoringEventSubscription& ev_sub, int& http_code);

  /*
   * Subscribe to UDM events
   * @param [std::string &] sub_id: ID of the created subscription (from AF)
   * @param [std::string &] nf_resource_location: Location of the created
   * subscription (generated by UDM)
   * @param [const oai::nef::model::MonitoringType_anyOf::eMonitoringType_anyOf
   * &] event_type: Event type
   * @param [const MonitoringEventSubscription&] ev_sub: Subscription
   * information (from AF)
   * @param [int&] http_code: HTTP response code from UDM
   * @return void
   */
  void subscribe_udm_events(
      const std::string& sub_id, std::string& nf_resource_location,
      const oai::nef::model::MonitoringType_anyOf::eMonitoringType_anyOf&
          event_type,
      const MonitoringEventSubscription& ev_sub, int& http_code);

  /*
   * Unsubscribe to a particular event
   * @param [const std::string &] nf_resource_location: Location of the
   * subscription
   * @param [int&] http_code: HTTP response code from NF
   * @return void
   */
  void unsubscribe_nf_event(
      const std::string& nf_resource_location, int& http_code);

  /*
   * Validate the monitoring event subscription request (e.g., whether the
   * request parameters are in line with operator policies)
   * @param [const MonitoringEventSubscription&] ev_sub: Event Subscription info
   * @param [MonitoringEventSubscription&] created_ev_sub: Updated Subscription
   * info (if the request is valid)
   * @param [ProblemDetails&] problem_details: Store details of the error
   * @return true if the request parameters are valid, otherwise false
   */
  bool validate_monitoring_event_subscription(
      const MonitoringEventSubscription& ev_sub,
      MonitoringEventSubscription& created_ev_sub,
      ProblemDetails& problem_details);

  /*
   * Update a new value for a member of MonitoringEventSubscription
   * @param [const std::string &] path: member name
   * @param [const std::string &] value: new value
   * @param [std::shared_ptr<MonitoringEventSubscription>&] mes: Pointer to the
   * subscription to be updated
   * @return true if success, otherwise false
   */
  bool replace_subscription_info(
      const std::string& path, const std::string& value,
      std::shared_ptr<MonitoringEventSubscription>& mes);

  /*
   * Add a new member of MonitoringEventSubscription
   * @param [const std::string &] path: member name
   * @param [const std::string &] value: value
   * @param [std::shared_ptr<MonitoringEventSubscription>&] mes: Pointer to the
   * subscription to be updated
   * @return true if success, otherwise false
   */
  bool add_subscription_info(
      const std::string& path, const std::string& value,
      std::shared_ptr<MonitoringEventSubscription>& mes);

  /*
   * Remove a member of MonitoringEventSubscription
   * @param [const std::string &] path: member name
   * @param [const std::string &] value: value
   * @param [std::shared_ptr<MonitoringEventSubscription>&] mes: Pointer to the
   * subscription to be updated
   * @return true if success, otherwise false
   */
  bool remove_subscription_info(
      const std::string& path,
      std::shared_ptr<MonitoringEventSubscription>& mes);

  /*
   * Update a MonitoringEventSubscription
   * @param [std::string &] consumer_nf_id: ID of the Consumer NF (e.g., AF)
   * @param [std::string &] sub_id: ID of the subscription
   * @param [std::shared_ptr<MonitoringEventSubscription>&] mes: Pointer to the
   * subscription to be updated
   * @return true if success, otherwise false
   */
  bool update_monitoring_subscription(
      const std::string& consumer_nf_id, const std::string& sub_id,
      std::shared_ptr<MonitoringEventSubscription>& mes);

 private:
  /*
   * Generate a random UUID for NEF instance
   * @param [void]
   * @return void
   */
  void generate_uuid();

  util::uint_generator<uint32_t> evsub_id_generator;
  std::string nef_instance_id;  // NEF instance ID

  // NF's instance id <-> list of subscription IDs
  std::map<std::string, std::vector<std::string>> nef_subscriptions;
  mutable std::shared_mutex m_instance_id2nef_subscription;

  // Sub_id <->Subscription (Southbound APIs)
  std::map<std::string, std::shared_ptr<NefEventExposureSubsc>>
      subscrition_id2nef_subscription;
  mutable std::shared_mutex m_subscription_id2nef_subscription;

  // Event Sub<->list of Subscriptions (Southbound)
  std::map<NefEvent_anyOf::eNefEvent_anyOf, std::set<std::string>>
      event_sub2subscriptions;
  mutable std::shared_mutex m_event_sub2subscriptions;

  // Use 1 common shared_mutex for Northbound APIs
  mutable std::shared_mutex m_subscription_id2nef_monitoring_subscription;

  // Sub_id <->Subscription (for Northbound APIs)
  std::map<std::string, std::shared_ptr<MonitoringEventSubscription>>
      subscrition_id2nef_monitoring_subscription;

  // Consumer NF ID <->list of Subscriptions (Northbound)
  std::map<std::string, std::set<std::string>>
      nf_id2nef_monitoring_subscriptions;

  // Event Sub<->list of Subscriptions (Northbound)
  std::map<MonitoringType_anyOf::eMonitoringType_anyOf, std::set<std::string>>
      event_sub2monitoring_subscriptions;
  // mutable std::shared_mutex m_event_sub2monitoring_subscriptions;

  // Sub_id <->resource location (Subscription Correlation ID, Northbound)
  std::map<std::string, std::string>
      subscrition_id2nef_monitoring_resource_location;
  // mutable std::shared_mutex
  // m_subscrition_id2nef_monitoring_resource_location;
};
}  // namespace oai::nef::app
#include "nef_config.hpp"

#endif /* FILE_NEF_APP_HPP_SEEN */
