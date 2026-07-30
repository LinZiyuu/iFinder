/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "dnn_policy_decisions_handler.h"
#include <nlohmann/json.hpp>
#include "database_wrapper_abstraction.hpp"

extern std::unique_ptr<oai::pcf::app::database_wrapper_abstraction>
    db_connector;

namespace oai::pcf::provisioning::api {

using namespace oai::pcf::api;
using namespace oai::common::sbi;

oai::pcf::api::api_response
dnn_policy_decisions_handler::dnn_policy_decision_dnn_delete(
    const std::string& dnn) {
  return handle_request_with_error_handling([&]() -> bool {
    Logger::pcf_db().info("Deleting dnn policy decision with dnn %s", dnn);
    return db_connector->deleteDnnPolicyDecision(dnn);
  });
}

oai::pcf::api::api_response
dnn_policy_decisions_handler::dnn_policy_decision_dnn_get(
    const std::string& dnn) {
  return handle_request_with_error_handling_json_body([&]() -> nlohmann::json {
    nlohmann::json json_data = db_connector->getDnnPolicyDecision(dnn);
    Logger::pcf_db().info(
        "Dnn policy decision successfully retrieved: %s", json_data.dump());
    return json_data;
  });
}

oai::pcf::api::api_response
dnn_policy_decisions_handler::dnn_policy_decision_dnn_put(
    const std::string& dnn,
    const oai::pcf::provisioning::model::DnnPolicyDecision& dnnPolicyDecision) {
  if (dnn != dnnPolicyDecision.getDnn()) {
    api_response response;
    response.status_code = http_status_code::BAD_REQUEST;
    response.body        = "Decision and dnn do not match";
    return response;
  }

  return handle_request_with_error_handling([&]() -> bool {
    nlohmann::json json_data = dnnPolicyDecision;
    Logger::pcf_db().info("Updating dnn policy decision %s", json_data.dump());
    return db_connector->updateDnnPolicyDecision(dnnPolicyDecision);
  });
}

oai::pcf::api::api_response
dnn_policy_decisions_handler::dnn_policy_decision_post(
    const oai::pcf::provisioning::model::DnnPolicyDecision& dnnPolicyDecision) {
  return handle_request_with_error_handling([&]() -> bool {
    nlohmann::json json_data = dnnPolicyDecision;
    Logger::pcf_db().info("Creating dnn policy decision: %s", json_data.dump());
    return db_connector->createDnnPolicyDecision(dnnPolicyDecision);
  });
}

oai::pcf::api::api_response
dnn_policy_decisions_handler::dnn_policy_decisions_get() {
  return handle_request_with_error_handling_json_body([&]() -> nlohmann::json {
    nlohmann::json json_data = db_connector->getAllDnnPolicyDecisions();
    Logger::pcf_db().info(
        "All dnn policy decisions successfully retrieved: %s",
        json_data.dump());
    return json_data;
  });
}
}  // namespace oai::pcf::provisioning::api