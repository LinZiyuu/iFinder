/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include <cpr/cpr.h>

#include <future>
#include <string>
#include <thread>
#include <optional>

#include "3gpp_29.500.h"
#include "http_definitions.hpp"
#include "logger_base.hpp"

using namespace oai::common::sbi;

namespace oai::http {

const std::string MIME_BOUNDARY = "----Boundary";

class http_client : public std::enable_shared_from_this<http_client> {
 private:
  /*
   * Sends a synchronous (simple) HTTP request
   * @param [const method_e&] method: HTTP method
   * @param [const request&] request: HTTP Request
   * @return the corresponding Response
   */
  response send_simple_http_request(
      const method_e& method, const request& request);

  /*
   * Sends a synchronous HTTP request and waits
   * @param [const method_e&] method: HTTP method
   * @param [const request&] request: HTTP Request
   * @return the corresponding Response
   */
  response send_async_http_request(
      const method_e& method, const request& request);

  /*
   * Execute a MultiPerform request
   * @param [const std::shared_ptr<cpr::MultiPerform>&] multi_perform:
   * MultiPerform
   * @return the list of responses accordingly
   */
  std::vector<response> execute_http_request(
      const std::shared_ptr<cpr::MultiPerform>& multi_perform);

  /*
   * Prepare a session object
   * @param [const method_e&] method: HTTP method
   * @param [const request&] request: HTTP Request
   * @param [std::shared_ptr<cpr::Session>&] session: the corresponding session
   * object
   * @return void
   */
  void prepare_session(
      const method_e& method, const request& request,
      std::shared_ptr<cpr::Session>& session);

  oai::logger::printf_logger m_sbi_logger;
  int m_timeout_ms;
  std::string m_interface;
  uint8_t m_http_version;
  request_type_e m_request_type;
  bool m_enable_tls;
  std::optional<std::string>
      m_public_key_path;  // store the public key path when TLS is enabled
  inline static std::shared_ptr<http_client> instance;

 public:
  explicit http_client(
      oai::logger::printf_logger logger, int timeout_ms,
      const std::string& interface, uint8_t http_version,
      bool enable_tls             = false,
      request_type_e request_type = request_type_e::SIMPLE);

  virtual ~http_client();

  /*
   * Get a static instance
   * @param [const oai::logger::printf_logger&] logger: a logger
   * @param [int] timeout_ms: HTTP Timeout in ms
   * @param [const std::string&] interface: Interface's name
   * @param [uint8_t] http_version: HTTP version
   * @param [request_type_e ] request_type: Type of HTTP Request
   * @return an HTTP Client's instance
   */
  static std::shared_ptr<http_client> create_instance(
      const oai::logger::printf_logger& logger, int timeout_ms,
      const std::string& interface, uint8_t http_version,
      bool enable_tls             = false,
      request_type_e request_type = request_type_e::SIMPLE);

  /*
   * Sends a HTTP request
   * @param [const method_e&] method: HTTP method
   * @param [const request&] request: HTTP Request
   * @param [const std::shared_ptr<cpr::MultiPerform>&] multi_perform:
   * MultiPerform
   * @return the corresponding Response
   */
  response send_http_request(const method_e& method, const request& request);

  /*
   * Get HTTP response info from the corresponding CPR Response
   * @param [const cpr::Response&] cpr_resp: CPR Response
   * @param [response&] resp: HTTP Response
   * @return void
   */
  void get_response_info(const cpr::Response& cpr_resp, response& resp);

  /*
   * Add a session to a MultiPerform
   * @param [const method_e&] method: HTTP method
   * @param [const request&] request: HTTP Request
   * @param [const std::shared_ptr<cpr::MultiPerform>&] multi_perform:
   * MultiPerform
   * @return a shared_ptr pointed to the created session
   */
  std::shared_ptr<cpr::Session> add_session_to_multi_peform(
      const method_e& method, const request& request,
      const std::shared_ptr<cpr::MultiPerform>& multi_perform);

  /*
   * Remove a session from a MultiPerform
   * @param [const std::shared_ptr<cpr::Session>&] session: Session to be
   * removed
   * @param [const std::shared_ptr<cpr::MultiPerform>&] multi_perform:
   * MultiPerform
   * @return void
   */
  void remove_session_from_multi_peform(
      const std::shared_ptr<cpr::Session>& session,
      const std::shared_ptr<cpr::MultiPerform>& multi_perform);

  /*
   * Execute the respective HTTP request on all sessions in this
   * MultiPerform
   * @param [const std::shared_ptr<cpr::MultiPerform>&] multi_perform:
   * MultiPerform
   * @return the corresponding list of responses
   */
  std::vector<response> send_multi_peform_http_request(
      const std::shared_ptr<cpr::MultiPerform>& multi_perform);

  /*
   * Sets the correct headers for a JSON request
   * @param [const std::string&] uri: URI to send the request to
   * @param [const std::string&] body: JSON body
   * @return request object
   */
  static request prepare_json_request(
      const std::string& uri, const std::string& body = "");

  /*
   * Sets the correct headers for a multipart/related request
   * @param [const std::string&] uri: URI to send the request to
   * @param [const std::string&] body: body multipart/related body (including
   * boundaries)
   * @return request object
   */
  static request prepare_multipart_request(
      const std::string& uri, const std::string& body);
};
}  // namespace oai::http
