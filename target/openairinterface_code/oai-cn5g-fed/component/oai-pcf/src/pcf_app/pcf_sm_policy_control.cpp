/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "pcf_sm_policy_control.hpp"
#include "logger.hpp"
#include "pcf_config.hpp"
#include "sm_policy/policy_decision.hpp"
#include "SmPolicyDecision.h"

#include <boost/uuid/uuid_io.hpp>
#include <unordered_map>
#include <map>
#include <memory>
#include <string>
#include <optional>
#include "nlohmann/json.hpp"
#include "3gpp_29.500.h"
#include "ProblemDetails.h"
#include "http_client.hpp"

using namespace oai::pcf::app;
using namespace oai::pcf::app::sm_policy;
using namespace oai::config::pcf;
using namespace oai::model::pcf;
using namespace oai::model::common;
using namespace oai::http;

using namespace std;

extern std::shared_ptr<oai::http::http_client> http_client_inst;

//------------------------------------------------------------------------------
pcf_smpc::pcf_smpc(
    const std::shared_ptr<oai::pcf::app::sm_policy::policy_storage>&
        policy_storage,
    pcf_event& ev)
    : m_event_sub(ev) {
  m_policy_storage = policy_storage;

  std::function<void(const std::shared_ptr<policy_decision>& decision)> f =
      std::bind(&pcf_smpc::handle_policy_change, this, std::placeholders::_1);

  m_policy_storage->subscribe_to_decision_change(f);

  m_sm_session_binding_connection =
      m_event_sub.subscribe_sm_session_binding(boost::bind(
          &pcf_smpc::handle_session_binding_request, this,
          boost::placeholders::_1, boost::placeholders::_2,
          boost::placeholders::_3, boost::placeholders::_4,
          boost::placeholders::_5));

  m_sm_update_decision_connection =
      m_event_sub.subscribe_sm_update_decision(boost::bind(
          &pcf_smpc::handle_update_decision_request, this,
          boost::placeholders::_1, boost::placeholders::_2));
  // m_sm_session_binding_connection =
  //     m_event_sub.subscribe_sm_session_binding(f2);
}

void pcf_smpc::handle_policy_change(
    const std::shared_ptr<policy_decision>& /* decision */) {
  Logger::pcf_app().warn("Policy changed, but not implemented!");
}

sm_policy::status_code pcf_smpc::send_sm_policy_control_update_notify(
    const oai::pcf::app::sm_policy::individual_sm_association& association) {
  std::string uri =
      association.get_sm_policy_context_data().getNotificationUri() + "/update";
  nlohmann::json json_data;
  // to_json(json_data, association.decsion);
  nlohmann::json decision_json;
  to_json(decision_json, association.get_sm_policy_decision_dto());

  json_data["smPolicyDecision"] = decision_json;

  Logger::pcf_app().info(
      "Sending PCF SM policy association creation request: uri -> %s",
      uri.c_str());
  request req   = http_client_inst->prepare_json_request(uri, json_data.dump());
  response resp = http_client_inst->send_http_request(method_e::POST, req);

  if (resp.status_code == http_status_code::OK) {
    // TODO [PAS] check if for required headers
    Logger::pcf_app().info(
        "Successful SM Policy Update Notification for SUPI %s",
        association.get_sm_policy_context_data().getSupi().c_str());
    return status_code::CREATED;
  }

  // failure case
  ProblemDetails problem_details;
  from_json(resp.body, problem_details);

  std::string info;
  status_code response;
  switch (resp.status_code) {
    case http_status_code::FORBIDDEN:
      info     = "SM Policy Update Notification Forbidden";
      response = status_code::CONTEXT_DENIED;
      break;
    case http_status_code::BAD_REQUEST:
      if (problem_details.getCause() == "USER_UNKNOWN") {
        response = status_code::USER_UNKOWN;
        info     = "SM Policy Association Creation: Unknown User";
      } else {
        response = status_code::INVALID_PARAMETERS;
        info     = "SM Policy Update Notification: Bad Request";
      }
      break;
    case http_status_code::INTERNAL_SERVER_ERROR:
      response = status_code::INTERNAL_SERVER_ERROR;
      info     = "SM Policy Update Notification: Internal Error";
      break;
    default:
      response = status_code::INTERNAL_SERVER_ERROR;
      info =
          "SM Policy Update Notification: Unknown Error Code from "
          "SMF: " +
          std::to_string(resp.status_code);
  }

  Logger::pcf_app().warn(
      "%s -- Details: %s - %s", info.c_str(),
      problem_details.getCause().c_str(), problem_details.getDetail().c_str());
  return response;
}

void pcf_smpc::handle_session_binding_request(
    const std::optional<std::string>& ipv4,
    const std::optional<std::string>& supi,
    const std::optional<std::string>& dnn, std::optional<std::string>& assoc_id,
    oai::model::pcf::SmPolicyDecision& decision) {
  // TODO: support multiple sessions

  std::shared_ptr<std::string> association_id =
      m_policy_storage->find_association(ipv4, supi, dnn);

  if (!association_id) {
    Logger::pcf_app().debug(
        fmt::format("handle_session_binding_request, association_id is null"));
    return;
  }

  assoc_id = association_id->c_str();

  std::unique_lock lock_assocations(m_associations_mutex);
  auto iter = m_associations.find(association_id->c_str());
  if (iter == m_associations.end()) {
    Logger::pcf_app().info(fmt::format(
        "Could not find policy association: ID {} not found",
        association_id->c_str()));
    return;
  }

  decision = iter->second.get_sm_policy_decision_dto();

  // Get PCC from decision
}

void pcf_smpc::handle_update_decision_request(
    std::optional<std::string>& association_id,
    oai::model::pcf::SmPolicyDecision& decision) {
  // Fetch the association related to the decision
  std::unique_lock lock_assocations(m_associations_mutex);
  auto iter = m_associations.find(association_id.value());
  if (iter == m_associations.end()) {
    Logger::pcf_app().info(fmt::format(
        "Could not delete policy association: ID {} not found",
        association_id.value()));
    return;
  }

  iter->second.set_sm_policy_decision(decision);

  // TODO [PAS] confirm if the storage should be updated
  /**
   * The changes from the update policy authorisation request should be
   * be for an existing policy association for an existing PDU session.
   * THe SMF gets the updated policy decision from the PCF for which the
   * PCF reads the new decision from the policy storage. However the policy
   * storage persists over new UE connections.
   *
   * The TODO is to confirm if the policy storage should be updated with the
   * new decision and to look for an alternative way to store the updates for
   * the policy decisions that are not persisted.
   */
  auto context = iter->second.get_sm_policy_context_data();
  if (!context.getSupi().empty()) {
    m_policy_storage->insert_supi_decision(context.getSupi(), decision);
  } else if (!context.getDnn().empty()) {
    m_policy_storage->insert_dnn_decision(context.getDnn(), decision);
  } else {
    Logger::pcf_app().error("Failed to update policy decision");
  }

  // Send a notification to the SMF related to the updated decision
  const auto& association_ref = iter->second;
  auto ret = send_sm_policy_control_update_notify(association_ref);
  if (ret != status_code::CREATED) {
    Logger::pcf_app().error("Policy update notification failed");
  }
}

//------------------------------------------------------------------------------
status_code pcf_smpc::create_sm_policy_handler(
    const SmPolicyContextData& context, SmPolicyDecision& decision,
    std::string& association_id, std::string& problem_details) {
  std::shared_ptr<policy_decision> chosen_decision =
      m_policy_storage->find_policy(context);

  if (!chosen_decision) {
    problem_details = fmt::format(
        "SM policy request from SUPI {}: No policies found", context.getSupi());
    Logger::pcf_app().debug(fmt::format(problem_details));
    return status_code::CONTEXT_DENIED;
  }

  association_id = std::to_string(m_association_id_generator.get_uid());

  individual_sm_association assoc(context, *chosen_decision, association_id);

  status_code res = assoc.decide_policy(decision);

  // XXX: Perform session binding
  m_policy_storage->insert_associations(context, association_id);

  if (res != status_code::CREATED) {
    problem_details = fmt::format(
        "SM Policy request from SUPI {}: Invalid policy decision provisioned",
        context.getSupi());
    Logger::pcf_app().debug(fmt::format(problem_details));
  } else {
    std::unique_lock lock_assocations(m_associations_mutex);
    m_associations.insert(std::make_pair(association_id, assoc));

    Logger::pcf_app().info(fmt::format(
        "Created Policy Decision for SUPI {} with ID {}", context.getSupi(),
        association_id));
  }
  return res;
}

//------------------------------------------------------------------------------
sm_policy::status_code pcf_smpc::delete_sm_policy_handler(
    const std::string& id, const SmPolicyDeleteData& /* delete_data */,
    std::string& problem_details) {
  // TODO for now, just delete, ignore the delete_data
  std::unique_lock lock_associations(m_associations_mutex);
  auto iter = m_associations.find(id);
  if (iter == m_associations.end()) {
    problem_details =
        fmt::format("Could not delete policy association: ID {} not found", id);
    Logger::pcf_app().info(problem_details);
    return status_code::NOT_FOUND;
  }
  m_associations.erase(iter);
  Logger::pcf_app().info(
      fmt::format("Deleted policy association with ID {}", id));

  // TODO [PAS]: Perform session binding delete

  return status_code::OK;
}

//------------------------------------------------------------------------------
sm_policy::status_code pcf_smpc::get_sm_policy_handler(
    const std::string& id, SmPolicyControl& control,
    std::string& problem_details) {
  Logger::pcf_app().debug(fmt::format("get_sm_policy_handler: ID {}", id));
  std::shared_lock lock_associations(m_associations_mutex);
  auto iter = m_associations.find(id);
  if (iter == m_associations.end()) {
    problem_details = fmt::format(
        "Could not retrieve policy association: ID {} not found", id);
    Logger::pcf_app().info(problem_details);
    return status_code::NOT_FOUND;
  }
  control.setContext(iter->second.get_sm_policy_context_data());
  control.setPolicy(iter->second.get_sm_policy_decision_dto());

  Logger::pcf_app().info(
      fmt::format("Retrieved policy association with ID {}", id));

  return status_code::OK;
}

//------------------------------------------------------------------------------
sm_policy::status_code pcf_smpc::update_sm_policy_handler(
    const std::string& id, const SmPolicyUpdateContextData& update_context,
    SmPolicyDecision& decision, std::string& problem_details) {
  Logger::pcf_app().info("Entering update_sm_policy_handler");
  std::unique_lock lock_associations(m_associations_mutex);
  auto iter = m_associations.find(id);

  if (iter == m_associations.end()) {
    problem_details =
        fmt::format("Could not update policy association: ID {} not found", id);
    Logger::pcf_app().info(problem_details);
    return status_code::NOT_FOUND;
  }

  // TODO [PAS]: Perform session binding update

  SmPolicyDecision new_decision;

  return iter->second.redecide_policy(
      update_context, decision, problem_details);
}

//------------------------------------------------------------------------------
pcf_smpc::~pcf_smpc() {
  Logger::pcf_app().debug("Delete PCF SMPC instance...");
}
