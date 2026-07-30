/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include <boost/algorithm/string.hpp>
#include <boost/thread.hpp>
#include <boost/thread/future.hpp>
#include <nlohmann/json.hpp>
#include <regex>
#include <string>

#include "3gpp_29.500.h"
#include "ausf-http2-server.h"
#include "ausf_config.hpp"
#include "ausf_sbi_helper.hpp"
#include "logger.hpp"
#include "string.hpp"

using namespace nghttp2::asio_http2;
using namespace nghttp2::asio_http2::server;
using namespace oai::model::ausf;
using namespace oai::config;
using namespace oai::ausf::api;

//------------------------------------------------------------------------------
void ausf_http2_server::start() {
  boost::system::error_code ec;

  Logger::ausf_server().info("HTTP2 server being started");

  // Default API
  server.handle(
      ausf_sbi_helper::UEAuthenticationServiceBase +
          ausf_sbi_helper::AusfAuthPathUeAuthentications,
      [&](const request& request, const response& response) {
        request.on_data([&](const uint8_t* data, std::size_t len) {
          std::string msg((char*) data, len);
          try {
            std::vector<std::string> split_result;
            boost::split(
                split_result, request.uri().path, boost::is_any_of("/"));
            if (request.method().compare("POST") == 0 && len > 0) {
              AuthenticationInfo authentication_info = {};
              nlohmann::json::parse(msg.c_str()).get_to(authentication_info);
              this->ue_authentications_post_handler(
                  authentication_info, response);
            }
          } catch (std::exception& e) {
            Logger::ausf_server().warn(
                "Invalid request (error: %s)!", e.what());
            response.write_head(
                oai::common::sbi::http_status_code::BAD_REQUEST);
            response.end();
            return;
          }
        });
      });

  server.handle(
      ausf_sbi_helper::UEAuthenticationServiceBase +
          ausf_sbi_helper::AusfAuthPathUeAuthentications + "/",
      [&](const request& request, const response& response) {
        request.on_data([&](const uint8_t* data, std::size_t len) {
          std::string msg((char*) data, len);
          try {
            std::vector<std::string> split_result;
            boost::split(
                split_result, request.uri().path, boost::is_any_of("/"));
            if (request.method().compare("POST") == 0 && len > 0) {
              if (split_result[split_result.size() - 1].compare(
                      "eap-session") == 0) {
                EapSession eap_session = {};
                std::string auth_ctx_id =
                    split_result[split_result.size() - 2].c_str();
                nlohmann::json::parse(msg.c_str()).get_to(eap_session);
                this->eap_auth_method_handler(
                    auth_ctx_id, eap_session, response);
              } else if (
                  split_result[split_result.size() - 1].compare("deregister") ==
                  0) {
                DeregistrationInfo deregistration_info = {};
                nlohmann::json::parse(msg.c_str()).get_to(deregistration_info);
                this->ue_authentications_deregister_post_handler(
                    deregistration_info, response);
              }
            } else if (request.method().compare("PUT") == 0 && len > 0) {
              ConfirmationData confirmation_data = {};
              std::string auth_ctx_id =
                  split_result[split_result.size() - 2].c_str();
              nlohmann::json::parse(msg.c_str()).get_to(confirmation_data);
              this->ue_authentications_auth_ctx_id5g_aka_confirmation_put_handler(
                  auth_ctx_id, confirmation_data, response);
            }
          } catch (std::exception& e) {
            Logger::ausf_server().warn(
                "Invalid request (error: %s)!", e.what());
            response.write_head(
                oai::common::sbi::http_status_code::BAD_REQUEST);
            response.end();
            return;
          }
        });
      });

  server.handle(
      ausf_sbi_helper::UEAuthenticationServiceBase + NAUSF_RG_AUTH,
      [&](const request& request, const response& response) {
        request.on_data([&](const uint8_t* data, std::size_t len) {
          std::string msg((char*) data, len);
          try {
            std::vector<std::string> split_result;
            boost::split(
                split_result, request.uri().path, boost::is_any_of("/"));
            if (request.method().compare("POST") == 0 && len > 0) {
              RgAuthenticationInfo rg_authentication_info = {};
              std::string auth_ctx_id =
                  split_result[split_result.size() - 2].c_str();
              nlohmann::json::parse(msg.c_str()).get_to(rg_authentication_info);
              this->rg_authentications_post_handler(
                  rg_authentication_info, response);
            }
          } catch (std::exception& e) {
            Logger::ausf_server().warn(
                "Invalid request (error: %s)!", e.what());
            response.write_head(
                oai::common::sbi::http_status_code::BAD_REQUEST);
            response.end();
            return;
          }
        });
      });

  running_server = true;
  if (server.listen_and_serve(ec, m_address, std::to_string(m_port))) {
    Logger::ausf_server().debug("HTTP Server status: %s", ec.message());
  }
  running_server = false;
  Logger::ausf_server().info("HTTP2 server fully stopped");
}

//------------------------------------------------------------------------
void ausf_http2_server::stop() {
  server.stop();
  while (running_server) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  Logger::ausf_server().info("HTTP2 server should be fully stopped");
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

//------------------------------------------------------------------------
void ausf_http2_server::eap_auth_method_handler(
    const std::string& auth_ctx_id, const EapSession& eap_session,
    const response& response) {
  Logger::ausf_server().info("eap_auth_method");
  header_map h;
  response.write_head(oai::common::sbi::http_status_code::NOT_IMPLEMENTED, h);
  response.end("eap_auth_method API has not been implemented yet!");
}

//------------------------------------------------------------------------
void ausf_http2_server::rg_authentications_post_handler(
    const RgAuthenticationInfo& rg_authentication_info,
    const response& response) {
  Logger::ausf_server().info("rg_authentications_post");
  header_map h;
  response.write_head(oai::common::sbi::http_status_code::NOT_IMPLEMENTED, h);
  response.end("rg_authentications_post API has not been implemented yet!");
}

//------------------------------------------------------------------------
void ausf_http2_server::ue_authentications_deregister_post_handler(
    const DeregistrationInfo& deregistration_info, const response& response) {
  Logger::ausf_server().info("ue_authentications_deregister_post");
  header_map h;
  response.write_head(oai::common::sbi::http_status_code::NOT_IMPLEMENTED, h);
  response.end(
      "ue_authentications_deregister_post API has not been implemented yet!");
}

//------------------------------------------------------------------------
void ausf_http2_server::
    ue_authentications_auth_ctx_id5g_aka_confirmation_put_handler(
        const std::string& auth_ctx_id,
        const ConfirmationData& confirmation_data, const response& response) {
  Logger::ausf_server().info("Received 5g_aka_confirmation Request");
  Logger::ausf_server().info(
      "5gaka confirmation received with authctxID %s", auth_ctx_id.c_str());

  nlohmann::json json_data  = {};
  Pistache::Http::Code code = {};
  header_map h;

  m_ausf_app->handle_ue_authentications_confirmation(
      auth_ctx_id, confirmation_data, json_data, code);

  // ausf --> seaf
  std::string json_data_str = json_data.dump();
  Logger::ausf_server().debug(
      "5g-aka-confirmation response:\n %s", json_data_str);

  Logger::ausf_server().info(
      "Send 5g-aka-confirmation response to SEAF (Code %d)", (int) code);
  if (code == Pistache::Http::Code::Ok)
    response.write_head(oai::common::sbi::http_status_code::OK, h);
  else
    response.write_head(oai::common::sbi::http_status_code::FORBIDDEN, h);
  response.end(json_data_str.c_str());
}

//------------------------------------------------------------------------
void ausf_http2_server::ue_authentications_post_handler(
    const AuthenticationInfo& authentication_info, const response& response) {
  Logger::ausf_server().info("Received ue_authentications_post Request");

  std::string location            = {};
  nlohmann::json ue_auth_ctx_json = {};
  Pistache::Http::Code code       = {};
  header_map h;

  m_ausf_app->handle_ue_authentications(
      authentication_info, ue_auth_ctx_json, location, code, 2);

  std::string ue_auth_ctx_json_str = ue_auth_ctx_json.dump();
  Logger::ausf_server().debug("Auth response:\n %s", ue_auth_ctx_json_str);

  Logger::ausf_server().info(
      "Send Auth response to SEAF (Code %d)", (int) code);
  if (code == Pistache::Http::Code::Created)
    response.write_head(oai::common::sbi::http_status_code::CREATED, h);
  else
    response.write_head(oai::common::sbi::http_status_code::NOT_FOUND, h);
  response.end(ue_auth_ctx_json_str.c_str());
}
//------------------------------------------------------------------------
