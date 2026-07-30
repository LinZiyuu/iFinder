/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "events_subscription_document_api_handler.h"

namespace oai::pcf::api {

using namespace oai::model::pcf;
using namespace oai::model::common;
using namespace oai::common::sbi;
using namespace oai::pcf::app::policy_auth;

api_response events_subscription_document_api_handler::delete_events_subsc(
    const std::string& app_session_id) {
  api_response response;
  std::string content_type = "application/problem+json";

  nlohmann::json json_data;

  json_data["error"] = "API endpoint not implemented";

  response.headers.add<Pistache::Http::Header::ContentType>(
      Pistache::Http::Mime::MediaType(content_type));
  response.body        = json_data.dump();
  response.status_code = http_status_code::NOT_FOUND;

  return response;
}

api_response events_subscription_document_api_handler::update_events_subsc(
    const std::string& app_session_id,
    const EventsSubscReqData& events_subsc_req_data) {
  api_response response;
  std::string content_type = "application/problem+json";

  nlohmann::json json_data;

  json_data["error"] = "API endpoint not implemented";

  response.headers.add<Pistache::Http::Header::ContentType>(
      Pistache::Http::Mime::MediaType(content_type));
  response.body        = json_data.dump();
  response.status_code = http_status_code::NOT_FOUND;

  return response;
}

}  // namespace oai::pcf::api