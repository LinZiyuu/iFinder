/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "nef_app.hpp"

#include <unistd.h>

#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <chrono>

#include "3gpp_29.500.h"
#include "3gpp_29.510.h"
#include "3gpp_conversions.hpp"
#include "AmfCreateEventSubscription.h"
#include "MonitoringNotification.h"
#include "MonitoringType_anyOf.h"
#include "common_defs.h"
#include "logger.hpp"
#include "nef_client.hpp"
#include "nef_config.hpp"

using namespace oai::nef::app;

extern nef_app* nef_app_inst;
extern nef_config nef_cfg;
nef_client* nef_client_inst = nullptr;

//------------------------------------------------------------------------------
nef_app::nef_app(const std::string& config_file) {
  Logger::nef_app().startup("Starting...");

  try {
    nef_client_inst = new nef_client();
  } catch (std::exception& e) {
    Logger::nef_app().error("Cannot create NEF_APP: %s", e.what());
    throw;
  }

  // Generate NF instance Id
  generate_uuid();

  Logger::nef_app().startup("Started");
}

//------------------------------------------------------------------------------
nef_app::~nef_app() {
  Logger::nef_app().debug("Delete NEF_APP instance...");
  if (nef_client_inst) delete nef_client_inst;
}

//------------------------------------------------------------------------------
void nef_app::generate_uuid() {
  nef_instance_id = to_string(boost::uuids::random_generator()());
}

//------------------------------------------------------------------------------
void nef_app::generate_ev_subscription_id(std::string& sub_id) {
  sub_id = std::to_string(evsub_id_generator.get_uid());
  Logger::nef_app().debug("Generated Subscription ID %s", sub_id.c_str());
}

//------------------------------------------------------------------------------
evsub_id_t nef_app::generate_ev_subscription_id() {
  return evsub_id_generator.get_uid();
}

//------------------------------------------------------------------------------
void nef_app::handle_create_individual_subscription(
    std::string& sub_id, const NefEventExposureSubsc& ev_sub,
    NefEventExposureSubsc& created_ev_sub, const uint8_t http_version,
    int& http_code, ProblemDetails& problem_details) {
  Logger::nef_app().info(
      "Handle a request to Create an Individual Subscription (Event Exposure)");
  nlohmann::json json_tmp = {};
  to_json(json_tmp, ev_sub);
  Logger::nef_app().debug("Subscription info: %s", json_tmp.dump().c_str());

  // Generate a subscription ID Id and store the corresponding information in a
  // map (subscription id, info)
  generate_ev_subscription_id(sub_id);

  created_ev_sub = ev_sub;
  // TODO: update created subscription with corresponding info

  std::shared_ptr<NefEventExposureSubsc> ces =
      std::make_shared<NefEventExposureSubsc>(created_ev_sub);

  if (add_ee_subscription(sub_id, ces)) {
    Logger::nef_app().debug(
        "Created a new subscription with Subscription ID %s", sub_id.c_str());

    to_json(json_tmp, created_ev_sub);
    Logger::nef_app().debug(
        "Created subscription info: %s", json_tmp.dump().c_str());
    http_code = HTTP_STATUS_CODE_201_CREATED;

  } else {
    Logger::nef_app().debug("Error when creating a new subscription!");
    // TODO: Set corresponding Code
    http_code = HTTP_STATUS_CODE_500_INTERNAL_SERVER_ERROR;
    // ProblemDetails
  }
  return;
}

//------------------------------------------------------------------------------
void nef_app::handle_remove_individual_subscription(
    const std::string& sub_id, const uint8_t http_version, int& http_code,
    ProblemDetails& problem_details) {
  if (remove_ee_subscription(sub_id)) {
    Logger::nef_app().debug(
        "Successfully removed subscription with Subscription ID %s", sub_id);
    http_code = HTTP_STATUS_CODE_204_NO_CONTENT;

  } else {
    Logger::nef_app().debug("Error when deleting a new subscription!");
    // TODO: Set corresponding Code
    http_code = HTTP_STATUS_CODE_500_INTERNAL_SERVER_ERROR;
    // ProblemDetails
  }
  return;
}

//------------------------------------------------------------------------------
void nef_app::handle_get_individual_subscription(
    const std::string& sub_id, nlohmann::json& ev_sub,
    const uint8_t http_version, int& http_code,
    ProblemDetails& problem_details) {
  if (get_ee_subscription(sub_id, ev_sub)) {
    Logger::nef_app().debug(
        "Found subscription with Subscription ID %s ", sub_id.c_str());
    Logger::nef_app().debug("Subscription info: %s ", ev_sub.dump().c_str());
    http_code = HTTP_STATUS_CODE_200_OK;
  } else {
    Logger::nef_app().debug(
        "Subscription not found with Subscription ID %s", sub_id.c_str());
    http_code = HTTP_STATUS_CODE_404_NOT_FOUND;
    // TODO: ProblemDetails
  }
  return;
}

//------------------------------------------------------------------------------
void nef_app::handle_update_individual_subscription(
    const std::string& sub_id, const NefEventExposureSubsc& ev_sub,
    nlohmann::json& updated_ev_sub, const uint8_t http_version,
    int& http_code) {
  nlohmann::json json_tmp = {};
  // First remove the old subscription
  if (remove_ee_subscription(sub_id)) {
    Logger::nef_app().debug(
        "Successfully removed subscription with Subscription ID %s", sub_id);
  } else {
    Logger::nef_app().debug("Error when deleting a new subscription!");
    // TODO: Set corresponding Code
    http_code = HTTP_STATUS_CODE_500_INTERNAL_SERVER_ERROR;
    return;
  }
  // Then create a new one
  NefEventExposureSubsc created_ev_sub = ev_sub;
  // TODO: update created subscription with corresponding info

  std::shared_ptr<NefEventExposureSubsc> ces =
      std::make_shared<NefEventExposureSubsc>(created_ev_sub);

  if (add_ee_subscription(sub_id, ces)) {
    Logger::nef_app().debug(
        "Updated a new subscription with Subscription ID %s", sub_id);

    to_json(json_tmp, created_ev_sub);
    Logger::nef_app().debug(
        "Updated subscription info: %s", json_tmp.dump().c_str());
  } else {
    Logger::nef_app().debug("Error when updating a new subscription!");
    // TODO: Set corresponding Code
    http_code = HTTP_STATUS_CODE_500_INTERNAL_SERVER_ERROR;
    return;
  }

  http_code = HTTP_STATUS_CODE_200_OK;

  return;
}

//------------------------------------------------------------------------------
void nef_app::handle_nf_event_notification(
    const NefEventExposureNotif& eventNotif, nlohmann::json& response_data,
    const uint8_t http_version, int& http_code) {
  // Process the Notification data

  // Send Notification to the subscribed NFs
}

//------------------------------------------------------------------------------
void nef_app::handle_amf_event_notification(
    const AmfEventNotification& amfEventNotification,
    nlohmann::json& response_data, const uint8_t http_version, int& http_code) {
  // Process the Notification data
  std::string sub_id = {};
  if (amfEventNotification.notifyCorrelationIdIsSet()) {
    sub_id = amfEventNotification.getNotifyCorrelationId();
  } else if (amfEventNotification.subsChangeNotifyCorrelationIdIsSet()) {
    sub_id = amfEventNotification.getSubsChangeNotifyCorrelationId();
  } else {
    Logger::nef_app().warn("Couldn't get NotifyCorrelationID");
    return;
  }

  // Get the subscription information
  std::shared_ptr<MonitoringEventSubscription> mes = {};
  // TODO: do we need consumer_nf_id
  std::string consumer_nf_id = {};
  if (!nef_app::get_monitoring_ee_subscription(consumer_nf_id, sub_id, mes)) {
    Logger::nef_app().warn("Couldn't get corresponding subscription");
    return;
  }
  std::string notification_uri = mes->getNotificationDestination();

  // Send Notification to the subscribed NFs
  // create MonitoringNotification
  MonitoringNotification monitoring_notification = {};
  monitoring_notification.setSubscription(
      nef_cfg.get_event_exposure_subscription_notify_url() + "/" + sub_id);
  std::vector<MonitoringEventReport> monitoring_reports;
  // monitoringEventReports MonitoringEventReport[]
  for (auto amf_report : amfEventNotification.getReportList()) {
    MonitoringEventReport monitoring_report = {};
    xgpp_conv::amf_report_to_monitoring_report(amf_report, monitoring_report);
    monitoring_reports.push_back(monitoring_report);
  }
  monitoring_notification.setMonitoringEventReports(monitoring_reports);

  // TODO: store at UDR
  // Send the report to the subscribed NF
  nlohmann::json json_body = {};
  to_json(json_body, monitoring_notification);

  nef_client_inst->send_event_exposure_notify(json_body, notification_uri);
  return;
}

//------------------------------------------------------------------------------
void nef_app::handle_smf_event_notification(
    const NsmfEventExposureNotification& smfEventExposureNotification,
    nlohmann::json& response_data, const uint8_t http_version, int& http_code) {
  // Process the Notification data

  // Send Notification to the subscribed NFs
}

//------------------------------------------------------------------------------
void nef_app::handle_udm_event_notification(
    const std::vector<MonitoringReport>& eventExposureNotif,
    nlohmann::json& response_data, const uint8_t http_version, int& http_code) {
  // Process the Notification data

  // Send Notification to the subscribed NFs
}

//------------------------------------------------------------------------------
void nef_app::handle_create_monitoring_event_subscription(
    const std::string& consumer_nf_id, std::string& sub_id,
    const MonitoringEventSubscription& ev_sub,
    MonitoringEventSubscription& created_ev_sub, const uint8_t http_version,
    int& http_code, ProblemDetails& problem_details) {
  Logger::nef_app().info(
      "Handle a request to create a Monitoring Event Subscription");
  nlohmann::json json_tmp = {};
  to_json(json_tmp, ev_sub);
  Logger::nef_app().debug("Subscription info: %s", json_tmp.dump().c_str());

  if (!validate_monitoring_event_subscription(
          ev_sub, created_ev_sub, problem_details)) {
    Logger::nef_app().warn("Subscription request is invalid!");
    return;
  }

  // Generate a subscription ID Id
  generate_ev_subscription_id(sub_id);

  // Subscribe to the corresponding NF (e.g., UDM/AMF/SMF) and receive the
  // notification
  std::string nf_resource_location =
      {};  // including Subscription Correlation ID

  subscribe_nf_events(ev_sub, sub_id, nf_resource_location, http_code);

  if ((http_code != 200) and (http_code != 201) and (http_code != 204)) {
    // TODO
    // Cannot subscribe to the corresponding NF
    Logger::nef_app().warn("Error when subscribe to the corresponding event!");
    // Don't need to remove generated Subscription Id
    return;
  }

  // Successfully subscribed to the corresponding NF
  created_ev_sub.setSelf(sub_id);
  // Store resource location
  std::shared_ptr<MonitoringEventSubscription> ces =
      std::make_shared<MonitoringEventSubscription>(created_ev_sub);

  if (add_ee_subscription(consumer_nf_id, sub_id, nf_resource_location, ces)) {
    Logger::nef_app().debug(
        "Created a new subscription with Subscription ID %s", sub_id.c_str());

    to_json(json_tmp, created_ev_sub);
    Logger::nef_app().debug(
        "Created subscription info: %s", json_tmp.dump().c_str());
    http_code = HTTP_STATUS_CODE_201_CREATED;
    // TODO: immediate report is included (HTTP code 200)

  } else {
    Logger::nef_app().debug("Error when creating a new subscription!");
    // TODO: Set corresponding Code
    http_code = HTTP_STATUS_CODE_500_INTERNAL_SERVER_ERROR;
    // ProblemDetails
  }
  return;
}

//------------------------------------------------------------------------------
void nef_app::handle_fetch_all_monitoring_event_subscriptions(
    const std::string& consumer_nf_id,
    const std::optional<std::vector<IpAddr>>& ipAddrs,
    const std::optional<std::string>& ipDomain,
    const std::optional<std::vector<std::string>>& macAddrs,
    const uint8_t http_version, nlohmann::json& result, int& http_code) {
  // TODO: IpAddr, IpDomain, macAddrs

  // Get all Sub Ids
  std::set<std::string> sub_ids;
  if (!get_sub_ids(consumer_nf_id, sub_ids)) {
    Logger::nef_app().debug(
        "No subscription available for this NF (Consumer NF ID %s)",
        consumer_nf_id.c_str());
    http_code = HTTP_STATUS_CODE_404_NOT_FOUND;
    // TODO
    return;
  }

  nlohmann::json subscriptions = nlohmann::json::array();
  for (auto s : sub_ids) {
    nlohmann::json tmp = {};
    if (get_monitoring_ee_subscription(consumer_nf_id, s, tmp)) {
      subscriptions.push_back(tmp);
    }
  }
  result    = subscriptions;
  http_code = HTTP_STATUS_CODE_200_OK;
  return;
}

//------------------------------------------------------------------------------
void nef_app::handle_delete_ind_monitoring_event_subscription(
    const std::string& consumer_nf_id, const std::string& sub_id,
    const uint8_t http_version, int& http_code,
    ProblemDetails& problem_details) {
  // Unsubscribe to the corresponding event from service provider
  if (subscrition_id2nef_monitoring_resource_location.count(sub_id) > 0) {
    int http_code = 0;
    unsubscribe_nf_event(
        subscrition_id2nef_monitoring_resource_location.at(sub_id), http_code);
  }

  if (remove_monitoring_ee_subscription(consumer_nf_id, sub_id)) {
    Logger::nef_app().debug(
        "Successfully removed monitoring subscription with Consumer NF ID %s, "
        "Subscription ID %s",
        consumer_nf_id.c_str(), sub_id);
  } else {
    Logger::nef_app().debug("Error when deleting a new subscription!");
    // TODO: Set corresponding Code
    http_code = HTTP_STATUS_CODE_500_INTERNAL_SERVER_ERROR;
    // TODO:  ProblemDetails
    return;
  }
}

//------------------------------------------------------------------------------
void nef_app::handle_fetch_ind_monitoring_event_subscription(
    const std::string& consumer_nf_id, const std::string& sub_id,
    const uint8_t http_version, nlohmann::json& response_data, int& http_code) {
  if (get_monitoring_ee_subscription(consumer_nf_id, sub_id, response_data)) {
    Logger::nef_app().debug(
        "Found subscription with Consumer NF ID %s, Subscription ID %s ",
        consumer_nf_id.c_str(), sub_id.c_str());
    Logger::nef_app().debug(
        "Subscription info: %s ", response_data.dump().c_str());
    http_code = HTTP_STATUS_CODE_200_OK;
  } else {
    Logger::nef_app().debug(
        "Subscription not found with Consumer NF ID %s, Subscription ID %s",
        consumer_nf_id.c_str(), sub_id.c_str());
    http_code = HTTP_STATUS_CODE_404_NOT_FOUND;
  }
  return;
}

//------------------------------------------------------------------------------
void nef_app::handle_modify_ind_monitoring_event_subscription(
    const std::string& consumer_nf_id, const std::string& sub_id,
    const std::vector<PatchItem>& patchItem, const uint8_t http_version,
    int& http_code, ProblemDetails& problem_details) {
  Logger::nef_app().info(
      "Handle Update Monitoring Event Exposure subscription (HTTP version %d)",
      http_version);

  // Find the subscription
  std::shared_ptr<MonitoringEventSubscription> mes = {};
  if (!get_monitoring_ee_subscription(consumer_nf_id, sub_id, mes)) {
    Logger::nef_app().debug(
        "Subscription not found with Consumer NF ID %s, Subscription ID %s",
        consumer_nf_id.c_str(), sub_id.c_str());
    http_code = HTTP_STATUS_CODE_404_NOT_FOUND;
    return;
  }

  bool op_success = true;

  for (auto p : patchItem) {
    patch_op_type_t op = xgpp_conv::string_to_patch_operation(p.getOp());
    // Verify Path
    if ((p.getPath().substr(0, 1).compare("/") != 0) or
        (p.getPath().length() < 2)) {
      Logger::nef_app().warn(
          "Bad value for operation path: %s ", p.getPath().c_str());
      http_code = HTTP_STATUS_CODE_400_BAD_REQUEST;
      problem_details.setCause(
          protocol_application_error_e2str[MANDATORY_IE_INCORRECT]);
      return;
    }

    std::string path = p.getPath().substr(1);

    switch (op) {
      case PATCH_OP_REPLACE: {
        if (replace_subscription_info(path, p.getValue(), mes)) {
          update_monitoring_subscription(consumer_nf_id, sub_id, mes);
          http_code = HTTP_STATUS_CODE_200_OK;
        } else {
          op_success = false;
        }
      } break;

      case PATCH_OP_ADD: {
        if (add_subscription_info(path, p.getValue(), mes)) {
          update_monitoring_subscription(consumer_nf_id, sub_id, mes);
          http_code = HTTP_STATUS_CODE_200_OK;
        } else {
          op_success = false;
        }
      } break;

      case PATCH_OP_REMOVE: {
        if (remove_subscription_info(path, mes)) {
          update_monitoring_subscription(consumer_nf_id, sub_id, mes);
          // http_code = HTTP_STATUS_CODE_200_OK;
        } else {
          op_success = false;
        }
      } break;

      default: {
        Logger::nef_app().warn("Requested operation is not valid!");
        op_success = false;
      }
    }

    if (!op_success) {
      http_code = HTTP_STATUS_CODE_400_BAD_REQUEST;
      problem_details.setCause(
          protocol_application_error_e2str[MANDATORY_IE_INCORRECT]);
    }
  }
}

//------------------------------------------------------------------------------
void nef_app::handle_update_ind_monitoring_event_subscription(
    const std::string& consumer_nf_id, const std::string& sub_id,
    const MonitoringEventSubscription& ev_sub, const uint8_t http_version,
    nlohmann::json& response_data, int& http_code) {
  nlohmann::json json_tmp = {};
  // First remove the old subscription
  if (remove_monitoring_ee_subscription(consumer_nf_id, sub_id)) {
    Logger::nef_app().debug(
        "Successfully removed monitoring subscription with Consumer NF ID %s, "
        "Subscription ID %s",
        consumer_nf_id.c_str(), sub_id);
  } else {
    Logger::nef_app().debug("Error when deleting a new subscription!");
    // TODO: Set corresponding Code
    http_code = HTTP_STATUS_CODE_500_INTERNAL_SERVER_ERROR;
    return;
  }
  // Then create a new one
  MonitoringEventSubscription created_ev_sub = ev_sub;
  // TODO: update created subscription with corresponding info
  // TODO:
  std::string nf_resource_location = {};
  std::shared_ptr<MonitoringEventSubscription> ces =
      std::make_shared<MonitoringEventSubscription>(created_ev_sub);

  if (add_ee_subscription(consumer_nf_id, sub_id, nf_resource_location, ces)) {
    Logger::nef_app().debug(
        "Created a new subscription with Subscription ID %s", sub_id.c_str());

    to_json(json_tmp, created_ev_sub);
    Logger::nef_app().debug(
        "Created subscription info: %s", json_tmp.dump().c_str());
    http_code = HTTP_STATUS_CODE_201_CREATED;
    // TODO: immediate report is included (HTTP code 200)

  } else {
    Logger::nef_app().debug("Error when creating a new subscription!");
    // TODO: Set corresponding Code
    http_code = HTTP_STATUS_CODE_500_INTERNAL_SERVER_ERROR;
    // ProblemDetails
  }
  return;
}

//------------------------------------------------------------------------------
bool nef_app::add_ee_subscription(
    const std::string& sub_id, std::shared_ptr<NefEventExposureSubsc>& ces) {
  std::unique_lock lock(m_subscription_id2nef_subscription);
  subscrition_id2nef_subscription[sub_id] = ces;

  // store subscription per event
  std::vector<NefEventSubs> event_subs = ces->getEventsSubs();
  for (auto e : event_subs) {
    NefEvent_anyOf::eNefEvent_anyOf value = e.getEvent().getEnumValue();
    event_sub2subscriptions[value].insert(sub_id);
  }
  return true;
}

//------------------------------------------------------------------------------
bool nef_app::remove_ee_subscription(const std::string& sub_id) {
  std::unique_lock lock(m_subscription_id2nef_subscription);
  if (subscrition_id2nef_subscription.count(sub_id) > 0) {
    // remove the list of subscriptions per event first
    std::shared_ptr<NefEventExposureSubsc> ces = {};
    ces = subscrition_id2nef_subscription.at(sub_id);
    std::vector<NefEventSubs> event_subs = ces->getEventsSubs();
    for (auto e : event_subs) {
      NefEvent_anyOf::eNefEvent_anyOf value = e.getEvent().getEnumValue();
      event_sub2subscriptions[value].erase(sub_id);
    }
    // then remove the subscription info
    subscrition_id2nef_subscription.erase(sub_id);
    return true;
  }
  return false;
}

//------------------------------------------------------------------------------
bool nef_app::get_ee_subscription(
    const std::string& sub_id, nlohmann::json& ev_sub) {
  std::shared_lock lock(m_subscription_id2nef_subscription);
  if (subscrition_id2nef_subscription.count(sub_id) > 0) {
    to_json(ev_sub, *subscrition_id2nef_subscription[sub_id]);
    return true;
  }
  return false;
}

//------------------------------------------------------------------------------
bool nef_app::add_ee_subscription(
    const std::string& consumer_nf_id, const std::string& sub_id,
    const std::string& nf_resource_location,
    std::shared_ptr<MonitoringEventSubscription>& ces) {
  std::unique_lock lock(m_subscription_id2nef_monitoring_subscription);
  subscrition_id2nef_monitoring_subscription[sub_id] = ces;

  // Store subscription per event
  MonitoringType monitoring_type = ces->getMonitoringType();
  MonitoringType_anyOf::eMonitoringType_anyOf value =
      monitoring_type.getEnumValue();
  event_sub2monitoring_subscriptions[value].insert(sub_id);

  // Store the association between NF Id and subscription ID
  nf_id2nef_monitoring_subscriptions[consumer_nf_id].insert(sub_id);

  // Associate NF Resource location with sub_id
  subscrition_id2nef_monitoring_resource_location[sub_id] =
      nf_resource_location;
  return true;
}

//------------------------------------------------------------------------------
bool nef_app::remove_monitoring_ee_subscription(
    const std::string& consumer_nf_id, const std::string& sub_id) {
  std::unique_lock lock(m_subscription_id2nef_monitoring_subscription);

  if (subscrition_id2nef_monitoring_subscription.count(sub_id) > 0) {
    std::shared_ptr<MonitoringEventSubscription> ces =
        subscrition_id2nef_monitoring_subscription.at(sub_id);

    // Remove subscription per event
    MonitoringType monitoring_type = ces->getMonitoringType();
    MonitoringType_anyOf::eMonitoringType_anyOf value =
        monitoring_type.getEnumValue();
    if (event_sub2monitoring_subscriptions.count(value) > 0) {
      event_sub2monitoring_subscriptions[value].erase(sub_id);
    }
    if (nf_id2nef_monitoring_subscriptions.count(consumer_nf_id)) {
      // Remove  the association between NF Id and subscription ID
      nf_id2nef_monitoring_subscriptions[consumer_nf_id].erase(sub_id);
    }

    // Remove NF Resource location associated with sub_id
    if (subscrition_id2nef_monitoring_resource_location.count(sub_id) > 0) {
      subscrition_id2nef_monitoring_resource_location.erase(sub_id);
    }

    // Finally remove the subscription
    subscrition_id2nef_monitoring_subscription.erase(sub_id);
    return true;
  }
  return false;
}

//------------------------------------------------------------------------------
bool nef_app::get_monitoring_ee_subscription(
    const std::string& consumer_nf_id, const std::string& sub_id,
    std::shared_ptr<MonitoringEventSubscription>& mes) {
  std::shared_lock lock(m_subscription_id2nef_monitoring_subscription);
  if (subscrition_id2nef_monitoring_subscription.count(sub_id) > 0) {
    mes = subscrition_id2nef_monitoring_subscription[sub_id];
    if (mes.get() == nullptr) return false;
    return true;
  }
  return false;
}

//------------------------------------------------------------------------------
bool nef_app::get_monitoring_ee_subscription(
    const std::string& consumer_nf_id, const std::string& sub_id,
    nlohmann::json& ev_sub) {
  std::shared_lock lock(m_subscription_id2nef_monitoring_subscription);
  if (subscrition_id2nef_monitoring_subscription.count(sub_id) > 0) {
    to_json(ev_sub, *subscrition_id2nef_monitoring_subscription[sub_id]);
    return true;
  }
  return false;
}

//------------------------------------------------------------------------------
bool nef_app::get_sub_ids(
    const std::string& consumer_nf_id, std::set<std::string>& sub_ids) {
  std::shared_lock lock(m_subscription_id2nef_monitoring_subscription);
  if (nf_id2nef_monitoring_subscriptions.count(consumer_nf_id)) {
    sub_ids = nf_id2nef_monitoring_subscriptions[consumer_nf_id];
    return true;
  }
  return false;
}

//------------------------------------------------------------------------------
void nef_app::subscribe_nf_events(
    const MonitoringEventSubscription& ev_sub, const std::string& sub_id,
    std::string& nf_resource_location, int& http_code) {
  MonitoringType monitoring_type = ev_sub.getMonitoringType();
  MonitoringType_anyOf::eMonitoringType_anyOf event_type =
      monitoring_type.getEnumValue();

  switch (event_type) {
    case oai::nef::model::MonitoringType_anyOf::eMonitoringType_anyOf::
        UE_REACHABILITY: {  // AMF/UDM
      subscribe_amf_events(
          sub_id, nf_resource_location, event_type, ev_sub, http_code);
      // UDM??
    } break;

    case oai::nef::model::MonitoringType_anyOf::eMonitoringType_anyOf::
        LOCATION_REPORTING: {  // AMF, GMLC
      subscribe_amf_events(
          sub_id, nf_resource_location, event_type, ev_sub, http_code);
    } break;

    case oai::nef::model::MonitoringType_anyOf::eMonitoringType_anyOf::
        CHANGE_OF_IMSI_IMEI_ASSOCIATION:  // UDM
    case oai::nef::model::MonitoringType_anyOf::eMonitoringType_anyOf::
        ROAMING_STATUS: {  // UDM
      subscribe_udm_events(
          sub_id, nf_resource_location, event_type, ev_sub, http_code);
    } break;

    case oai::nef::model::MonitoringType_anyOf::eMonitoringType_anyOf::
        LOSS_OF_CONNECTIVITY:  // AMF
    case oai::nef::model::MonitoringType_anyOf::eMonitoringType_anyOf::
        COMMUNICATION_FAILURE:  // AMF
    case oai::nef::model::MonitoringType_anyOf::eMonitoringType_anyOf::
        AVAILABILITY_AFTER_DDN_FAILURE:  // AMF
    case oai::nef::model::MonitoringType_anyOf::eMonitoringType_anyOf::
        NUMBER_OF_UES_IN_AN_AREA: {  // AMF
      subscribe_amf_events(
          sub_id, nf_resource_location, event_type, ev_sub, http_code);
    } break;

    case oai::nef::model::MonitoringType_anyOf::eMonitoringType_anyOf::
        PDN_CONNECTIVITY_STATUS:  // SMF
    case oai::nef::model::MonitoringType_anyOf::eMonitoringType_anyOf::
        DOWNLINK_DATA_DELIVERY_STATUS:  // SMF
    case oai::nef::model::MonitoringType_anyOf::eMonitoringType_anyOf::
        API_SUPPORT_CAPABILITY: {  // SMF
      subscribe_smf_events(
          sub_id, nf_resource_location, event_type, ev_sub, http_code);
    } break;

    case oai::nef::model::MonitoringType_anyOf::eMonitoringType_anyOf::
        NUM_OF_REGD_UES: {  // NSACF
      // TODO:
    } break;

    case oai::nef::model::MonitoringType_anyOf::eMonitoringType_anyOf::
        NUM_OF_ESTD_PDU_SESSIONS: {  // NSACF
      // TODO:
    } break;

    case oai::nef::model::MonitoringType_anyOf::eMonitoringType_anyOf::
        AREA_OF_INTEREST: {
      // TODO:
    } break;
    default: {
    }
  }
}

//------------------------------------------------------------------------------
void nef_app::subscribe_amf_events(
    const std::string& sub_id, std::string& nf_resource_location,
    const oai::nef::model::MonitoringType_anyOf::eMonitoringType_anyOf&
        event_type,
    const MonitoringEventSubscription& ev_sub, int& http_code) {
  // Fill message content and send an Event Exposure msg to AMF
  oai::nef::model::AmfCreateEventSubscription create_ev_subscription = {};
  xgpp_conv::monitoring_event_to_amf_event(ev_sub, create_ev_subscription);
  AmfEventSubscription ev_subscription =
      create_ev_subscription.getSubscription();
  // SubsChangeNotifyUri
  ev_subscription.setSubsChangeNotifyUri(
      nef_cfg.get_event_exposure_subscription_notify_url() + "/" + sub_id);
  // subsChangeNotifyCorelationId
  ev_subscription.setSubsChangeNotifyCorrelationId(sub_id);
  // NfId
  ev_subscription.setNfId(nef_instance_id);

  create_ev_subscription.setSubscription(ev_subscription);
  nlohmann::json json_body = {};
  to_json(json_body, create_ev_subscription);
  std::string amf_uri       = nef_cfg.get_amf_event_exposure_url();
  std::string response_data = {};

  nef_client_inst->send_event_exposure_subscribe(
      json_body, amf_uri, response_data, nf_resource_location, http_code);
  return;
}

//------------------------------------------------------------------------------
void nef_app::subscribe_smf_events(
    const std::string& sub_id, std::string& nf_resource_location,
    const oai::nef::model::MonitoringType_anyOf::eMonitoringType_anyOf&
        event_type,
    const MonitoringEventSubscription& ev_sub, int& http_code) {
  // TODO:
}

//------------------------------------------------------------------------------
void nef_app::subscribe_udm_events(
    const std::string& sub_id, std::string& nf_resource_location,
    const oai::nef::model::MonitoringType_anyOf::eMonitoringType_anyOf&
        event_type,
    const MonitoringEventSubscription& ev_sub, int& http_code) {
  // Fill message content and send an Event Exposure msg to UDM
  // TODO:
}

//------------------------------------------------------------------------------
void nef_app::unsubscribe_nf_event(
    const std::string& nf_resource_location, int& http_code) {
  std::string response_data = {};
  nef_client_inst->send_event_exposure_unsubscribe(
      nf_resource_location, response_data, http_code);
  // TODO: process the response data
  return;
}

//------------------------------------------------------------------------------
bool nef_app::validate_monitoring_event_subscription(
    const MonitoringEventSubscription& ev_sub,
    MonitoringEventSubscription& created_ev_sub,
    ProblemDetails& problem_details) {
  // TODO: Check request parameters and set the corresponding cause
  // TODO: Check monitoring event type and set the corresponding cause
  created_ev_sub = ev_sub;
  // TODO: update created subscription with corresponding info
  return true;
}

//------------------------------------------------------------------------------
bool nef_app::replace_subscription_info(
    const std::string& path, const std::string& value,
    std::shared_ptr<MonitoringEventSubscription>& mes) {
  //(3GPP TS 29.122) only update of a notification destination URI is supported
  if (path.compare("notificationDestination") == 0) {
    mes->setNotificationDestination(value);
    return true;
  }
  return false;
}

//------------------------------------------------------------------------------
bool nef_app::add_subscription_info(
    const std::string& path, const std::string& value,
    std::shared_ptr<MonitoringEventSubscription>& mes) {
  // TODO:
  return true;
}

//------------------------------------------------------------------------------
bool nef_app::remove_subscription_info(
    const std::string& path,
    std::shared_ptr<MonitoringEventSubscription>& mes) {
  //(3GPP TS 29.122) only partial cancellation within an active group initiated
  // by the SCS/AS are supported
  // TODO:
  return true;
}

//------------------------------------------------------------------------------
bool nef_app::update_monitoring_subscription(
    const std::string& consumer_nf_id, const std::string& sub_id,
    std::shared_ptr<MonitoringEventSubscription>& mes) {
  std::unique_lock lock(m_subscription_id2nef_monitoring_subscription);
  subscrition_id2nef_monitoring_subscription[sub_id] = mes;

  // TODO: Remove subscription per event (old value)
  MonitoringType monitoring_type = mes->getMonitoringType();
  MonitoringType_anyOf::eMonitoringType_anyOf value =
      monitoring_type.getEnumValue();
  event_sub2monitoring_subscriptions[value].insert(sub_id);
  return true;
}
