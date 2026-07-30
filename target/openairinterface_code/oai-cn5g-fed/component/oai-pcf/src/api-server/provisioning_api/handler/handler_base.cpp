/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "handler_base.hpp"
#include "database_wrapper.hpp"

extern std::unique_ptr<oai::pcf::app::database_wrapper_abstraction>
    db_connector;

namespace oai::pcf::provisioning::api {

using namespace oai::pcf::app;
using namespace oai::common::sbi;

oai::pcf::api::api_response handler_base::handle_request_with_error_handling(
    std::function<bool()> db_operation) {
  oai::pcf::api::api_response response;

  try {
    if (db_connector) {
      if (db_operation()) {
        response.status_code = http_status_code::OK;
      } else {
        response.status_code = http_status_code::CONFLICT;
      }
    } else {
      response.status_code = http_status_code::SERVICE_UNAVAILABLE;
    }
  } catch (const NotFoundException& e) {
    response.status_code = http_status_code::NOT_FOUND;
    response.body        = e.what();
  } catch (const AlreadyExistException& e) {
    response.status_code = http_status_code::CONFLICT;
    response.body        = e.what();
  } catch (const std::exception& e) {
    response.status_code = http_status_code::INTERNAL_SERVER_ERROR;
    response.body        = e.what();
  }

  return response;
}

oai::pcf::api::api_response
handler_base::handle_request_with_error_handling_json_body(
    std::function<nlohmann::json()> db_operation) {
  oai::pcf::api::api_response response;

  try {
    if (db_connector) {
      nlohmann::json json_data = db_operation();
      response.headers.add<Pistache::Http::Header::ContentType>(
          Pistache::Http::Mime::MediaType("application/json"));
      response.body        = json_data.dump();
      response.status_code = http_status_code::OK;
    } else {
      response.status_code = http_status_code::SERVICE_UNAVAILABLE;
    }
  } catch (const NotFoundException& e) {
    response.status_code = http_status_code::NOT_FOUND;
    response.body        = e.what();
  } catch (const AlreadyExistException& e) {
    response.status_code = http_status_code::CONFLICT;
    response.body        = e.what();
  } catch (const std::exception& e) {
    response.status_code = http_status_code::INTERNAL_SERVER_ERROR;
    response.body        = e.what();
  }

  return response;
}

}  // namespace oai::pcf::provisioning::api
