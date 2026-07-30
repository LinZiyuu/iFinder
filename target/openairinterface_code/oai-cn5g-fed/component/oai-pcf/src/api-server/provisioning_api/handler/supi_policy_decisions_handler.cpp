/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "supi_policy_decisions_handler.h"
#include <nlohmann/json.hpp>
#include "database_wrapper_abstraction.hpp"

extern std::unique_ptr<oai::pcf::app::database_wrapper_abstraction>
    db_connector;

namespace oai::pcf::provisioning::api {

using namespace oai::pcf::api;
using namespace oai::common::sbi;

oai::pcf::api::api_response
supi_policy_decisions_handler::supi_policy_decision_supi_get(
    const std::string& supi) {
  return handle_request_with_error_handling_json_body([&]() -> nlohmann::json {
    nlohmann::json json_data = db_connector->getSupiPolicyDecision(supi);
    Logger::pcf_db().info(
        "Supi policy decision successfully retrieved: %s", json_data.dump());
    return json_data;
  });
}

oai::pcf::api::api_response
supi_policy_decisions_handler::supi_policy_decision_supi_delete(
    const std::string& supi) {
  return handle_request_with_error_handling([&]() -> bool {
    Logger::pcf_db().info("Deleting supi policy decision with supi %s", supi);
    return db_connector->deleteSupiPolicyDecision(supi);
  });
}

oai::pcf::api::api_response
supi_policy_decisions_handler::supi_policy_decision_supi_put(
    const std::string& supi,
    const oai::pcf::provisioning::model::SupiPolicyDecision&
        supiPolicyDecision) {
  if (supi != supiPolicyDecision.getSupi()) {
    api_response response;
    response.status_code = http_status_code::BAD_REQUEST;
    response.body        = "Decision and supi do not match";
    return response;
  }

  return handle_request_with_error_handling([&]() -> bool {
    nlohmann::json json_data = supiPolicyDecision;
    Logger::pcf_db().info("Updating supi policy decision %s", json_data.dump());
    return db_connector->updateSupiPolicyDecision(supiPolicyDecision);
  });
}

oai::pcf::api::api_response
supi_policy_decisions_handler::supi_policy_decision_post(
    const oai::pcf::provisioning::model::SupiPolicyDecision&
        supiPolicyDecision) {
  return handle_request_with_error_handling([&]() -> bool {
    nlohmann::json json_data = supiPolicyDecision;
    Logger::pcf_db().info(
        "Creating supi policy decision: %s", json_data.dump());
    return db_connector->createSupiPolicyDecision(supiPolicyDecision);
  });
}

oai::pcf::api::api_response
supi_policy_decisions_handler::supi_policy_decisions_get() {
  return handle_request_with_error_handling_json_body([&]() -> nlohmann::json {
    nlohmann::json json_data = db_connector->getAllSupiPolicyDecisions();
    Logger::pcf_db().info(
        "All supi policy decisions successfully retrieved: %s",
        json_data.dump());
    return json_data;
  });
}
}  // namespace oai::pcf::provisioning::api