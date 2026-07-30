/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include "pcf_app.hpp"
#include "string.hpp"
#include "uint_generator.hpp"
#include <nghttp2/asio_http2_server.h>
#include "IndividualSMPolicyDocumentApiImpl.h"
#include "SMPoliciesCollectionApiImpl.h"
#include "sm_policies_collection_api_handler.h"
#include "individual_sm_policy_document_api_handler.h"
#include "application_sessions_collection_api_handler.h"
#include "events_subscription_document_api_handler.h"
#include "individual_application_session_context_document_api_handler.h"
#include "pcscf_restoration_indication_api_handler.h"
#include "provisioning_api/handler/default_policy_decisions_handler.h"
#include "provisioning_api/handler/dnn_policy_decisions_handler.h"
#include "provisioning_api/handler/slice_policy_decisions_handler.h"
#include "provisioning_api/handler/supi_policy_decisions_handler.h"
#include "provisioning_api/handler/pcc_rules_handler.h"
#include "provisioning_api/handler/qos_data_handler.h"
#include "provisioning_api/handler/traffic_control_data_handler.h"

namespace oai::pcf::api {

class pcf_http2_server {
 public:
  pcf_http2_server(
      const std::string& addr, uint32_t port,
      const std::unique_ptr<oai::pcf::app::pcf_app>& pcf_app_inst)
      : m_address(addr), m_port(port), server() {
    // TODO hardcode http string, how to handle https
    std::string address = "http://" + addr + ":" + std::to_string(port);

    m_collection_api_handler =
        std::make_shared<sm_policies_collection_api_handler>(
            pcf_app_inst->get_pcf_smpc_service(), address);

    m_individual_api_handler =
        std::make_shared<individual_sm_policy_document_api_handler>(
            pcf_app_inst->get_pcf_smpc_service());

    m_application_sessions_collection_api_handler =
        std::make_shared<application_sessions_collection_api_handler>(
            pcf_app_inst->get_pcf_policy_authorization_service(), address);

    m_events_subscription_document_api_handler =
        std::make_shared<events_subscription_document_api_handler>(
            pcf_app_inst->get_pcf_policy_authorization_service());

    m_individual_application_session_context_document_api_handler =
        std::make_shared<
            individual_application_session_context_document_api_handler>(
            pcf_app_inst->get_pcf_policy_authorization_service());

    m_pcscf_restoration_indication_api_handler =
        std::make_shared<pcscf_restoration_indication_api_handler>(
            pcf_app_inst->get_pcf_policy_authorization_service());

    m_default_policy_decisions_handler = std::make_shared<
        oai::pcf::provisioning::api::default_policy_decisions_handler>();
    m_dnn_policy_decisions_handler = std::make_shared<
        oai::pcf::provisioning::api::dnn_policy_decisions_handler>();
    m_slice_policy_decisions_handler = std::make_shared<
        oai::pcf::provisioning::api::slice_policy_decisions_handler>();
    m_supi_policy_decisions_handler = std::make_shared<
        oai::pcf::provisioning::api::supi_policy_decisions_handler>();
    m_pcc_rules_handler =
        std::make_shared<oai::pcf::provisioning::api::pcc_rules_handler>();
    m_qos_data_handler =
        std::make_shared<oai::pcf::provisioning::api::qos_data_handler>();
    m_traffic_control_data_handler = std::make_shared<
        oai::pcf::provisioning::api::traffic_control_data_handler>();
  };

  void start();
  void init(size_t /* thr */) {}

  // PCF

  void stop();

 private:
  oai::utils::uint_generator<uint32_t> m_promise_id_generator;
  std::string m_address;
  uint32_t m_port;
  bool running_server;

  nghttp2::asio_http2::server::http2 server;

  std::shared_ptr<sm_policies_collection_api_handler> m_collection_api_handler;
  std::shared_ptr<individual_sm_policy_document_api_handler>
      m_individual_api_handler;

  std::shared_ptr<application_sessions_collection_api_handler>
      m_application_sessions_collection_api_handler;
  std::shared_ptr<events_subscription_document_api_handler>
      m_events_subscription_document_api_handler;
  std::shared_ptr<individual_application_session_context_document_api_handler>
      m_individual_application_session_context_document_api_handler;
  std::shared_ptr<pcscf_restoration_indication_api_handler>
      m_pcscf_restoration_indication_api_handler;
  std::shared_ptr<oai::pcf::provisioning::api::default_policy_decisions_handler>
      m_default_policy_decisions_handler;
  std::shared_ptr<oai::pcf::provisioning::api::dnn_policy_decisions_handler>
      m_dnn_policy_decisions_handler;
  std::shared_ptr<oai::pcf::provisioning::api::slice_policy_decisions_handler>
      m_slice_policy_decisions_handler;
  std::shared_ptr<oai::pcf::provisioning::api::supi_policy_decisions_handler>
      m_supi_policy_decisions_handler;
  std::shared_ptr<oai::pcf::provisioning::api::pcc_rules_handler>
      m_pcc_rules_handler;
  std::shared_ptr<oai::pcf::provisioning::api::qos_data_handler>
      m_qos_data_handler;
  std::shared_ptr<oai::pcf::provisioning::api::traffic_control_data_handler>
      m_traffic_control_data_handler;

  static void handle_method_not_exists(
      const nghttp2::asio_http2::server::response& response,
      const nghttp2::asio_http2::server::request& request);

  static void handle_parsing_error(
      const nghttp2::asio_http2::server::response& response,
      const std::exception& ex);

  static nghttp2::asio_http2::header_map convert_headers(
      const api_response& response);

  static std::map<std::string, std::string> parse_query(
      const std::string& query);

  static void send_response(
      const nghttp2::asio_http2::server::response& response,
      const api_response& resp) {
    auto h_map = convert_headers(resp);
    response.write_head(static_cast<unsigned int>(resp.status_code), h_map);
    response.end(resp.body);
  }
};

}  // namespace oai::pcf::api
