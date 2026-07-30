/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "individual_application_session_context_document_api_handler.h"
#include "ProblemDetails.h"
#include "AppSessionContext.h"

namespace oai::pcf::api {

using namespace oai::model::pcf;
using namespace oai::model::common;
using namespace oai::common::sbi;
using namespace oai::pcf::app::policy_auth;

api_response
individual_application_session_context_document_api_handler::delete_app_session(
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

api_response
individual_application_session_context_document_api_handler::get_app_session(
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

api_response
individual_application_session_context_document_api_handler::mod_app_session(
    const std::string& app_session_id,
    const AppSessionContextUpdateDataPatch&
        app_session_context_update_data_patch) {
  api_response response;
  ProblemDetails problem_details;
  std::string problem_description;
  std::string content_type = "application/problem+json";
  nlohmann::json json_data;
  uint16_t http_code;

  AppSessionContext app_session_context;
  status_code res = m_pa_service->mod_app_session_handler(
      app_session_id, app_session_context_update_data_patch,
      app_session_context, problem_description);

  problem_details.setDetail(problem_description);

  switch (res) {
    case status_code::OK:
      content_type = "application/json";
      http_code    = http_status_code::OK;
      break;
    default:
      problem_details.setCause("INTERNAL_ERROR");
      http_code = http_status_code::INTERNAL_SERVER_ERROR;
  }

  if (res == status_code::OK) {
    to_json(json_data, app_session_context);
  } else {
    to_json(json_data, problem_details);
  }

  response.headers.add<Pistache::Http::Header::ContentType>(
      Pistache::Http::Mime::MediaType(content_type));
  response.body        = json_data.dump();
  response.status_code = http_code;
  return response;
}

}  // namespace oai::pcf::api