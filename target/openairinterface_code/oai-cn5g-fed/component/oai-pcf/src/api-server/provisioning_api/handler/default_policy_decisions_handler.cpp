/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "default_policy_decisions_handler.h"
#include "database_wrapper_abstraction.hpp"
#include <nlohmann/json.hpp>

extern std::unique_ptr<oai::pcf::app::database_wrapper_abstraction>
    db_connector;

namespace oai::pcf::provisioning::api {

using namespace oai::pcf::api;
using namespace oai::common::sbi;

api_response default_policy_decisions_handler::default_decision_get() {
  return handle_request_with_error_handling_json_body([&]() -> nlohmann::json {
    nlohmann::json json_data = db_connector->getDefaultPolicyDecision();
    Logger::pcf_db().info(
        "Default policy rules successfully retrieved: %s", json_data.dump());
    return json_data;
  });
}

api_response default_policy_decisions_handler::default_decision_put(
    const std::vector<std::string>& pccRules) {
  nlohmann::json json_data = pccRules;
  return handle_request_with_error_handling([&]() -> bool {
    Logger::pcf_db().info("Set default policy rules: %s", json_data.dump());
    return db_connector->setDefaultPolicyDecision(pccRules);
  });
}

}  // namespace oai::pcf::provisioning::api