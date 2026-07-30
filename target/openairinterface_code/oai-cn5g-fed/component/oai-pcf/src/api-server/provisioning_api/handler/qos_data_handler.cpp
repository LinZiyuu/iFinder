/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "qos_data_handler.h"
#include <nlohmann/json.hpp>
#include "database_wrapper_abstraction.hpp"

extern std::unique_ptr<oai::pcf::app::database_wrapper_abstraction>
    db_connector;

namespace oai::pcf::provisioning::api {

using namespace oai::pcf::api;
using namespace oai::common::sbi;

oai::pcf::api::api_response qos_data_handler::qos_data_qos_id_delete(
    const std::string& qosId) {
  return handle_request_with_error_handling([&]() -> bool {
    Logger::pcf_db().info("Deleting QoSData with id %s", qosId);
    return db_connector->deleteQosData(qosId);
  });
}

oai::pcf::api::api_response qos_data_handler::qos_data_qos_id_get(
    const std::string& qosId) {
  return handle_request_with_error_handling_json_body([&]() -> nlohmann::json {
    nlohmann::json json_data = db_connector->getQosData(qosId);
    Logger::pcf_db().info(
        "QoSData successfully retrieved: %s", json_data.dump());
    return json_data;
  });
}

oai::pcf::api::api_response qos_data_handler::qos_data_qos_id_put(
    const std::string& qosId, const oai::model::pcf::QosData& qosData) {
  if (qosId != qosData.getQosId()) {
    api_response response;
    response.status_code = http_status_code::BAD_REQUEST;
    response.body        = "Qos data and Id do not match";
    return response;
  }

  return handle_request_with_error_handling([&]() -> bool {
    nlohmann::json json_data = qosData;
    Logger::pcf_db().info("Updating QoSData %s", json_data.dump());
    return db_connector->updateQosData(qosData);
  });
}

oai::pcf::api::api_response qos_data_handler::qos_data_post(
    const oai::model::pcf::QosData& qosData) {
  return handle_request_with_error_handling([&]() -> bool {
    nlohmann::json json_data = qosData;
    Logger::pcf_db().info("Creating QosData:  %s", json_data.dump());
    return db_connector->createQosData(qosData);
  });
}

oai::pcf::api::api_response qos_data_handler::qos_data_get() {
  api_response response;
  return handle_request_with_error_handling_json_body([&]() -> nlohmann::json {
    nlohmann::json json_data = db_connector->getAllQosData();
    Logger::pcf_db().info(
        "All QoSData successfully retrieved: %s", json_data.dump());
    return json_data;
  });
}
}  // namespace oai::pcf::provisioning::api