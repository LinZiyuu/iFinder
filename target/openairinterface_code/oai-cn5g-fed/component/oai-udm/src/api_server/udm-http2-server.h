/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_UDM_HTTP2_SERVER_SEEN
#define FILE_UDM_HTTP2_SERVER_SEEN

#include "conversions.hpp"

#include "udm_app.hpp"
#include "udm.h"
#include <nghttp2/asio_http2_server.h>
#include "logger.hpp"

using namespace nghttp2::asio_http2;
using namespace nghttp2::asio_http2::server;
using namespace oai::udm::app;

class udm_http2_server {
 public:
  udm_http2_server(std::string addr, uint32_t port, udm_app* udm_app_inst)
      : m_address(addr), m_port(port), server(), m_udm_app(udm_app_inst) {}
  void start();
  void init(size_t thr) {}

  void generate_auth_data_request_handler(
      const std::string& supiOrSuci,
      const oai::model::udm::AuthenticationInfoRequest&
          authenticationInfoRequest,
      const response& response);

  void confirm_auth_handler(
      const std::string& supi, const oai::model::udm::AuthEvent& authEvent,
      const response& response);

  void delete_auth_handler(
      const std::string& supi, const std::string& authEventId,
      const oai::model::udm::AuthEvent& authEvent, const response& response);

  void access_mobility_subscription_data_retrieval_handler(
      const std::string& supi, const response& response,
      oai::model::common::PlmnId PlmnId = {});

  void amf_registration_for_3gpp_access_handler(
      const std::string& ue_id,
      const oai::model::udm::Amf3GppAccessRegistration&
          amf_3gpp_access_registration,
      const response& response);

  void session_management_subscription_data_retrieval_handler(
      const std::string& supi, const response& response,
      oai::model::common::Snssai snssai = {}, std::string dnn = {},
      oai::model::common::PlmnId PlmnId = {});

  void slice_selection_subscription_data_retrieval_handler(
      const std::string& supi, const response& response,
      std::string supported_features    = {},
      oai::model::common::PlmnId PlmnId = {});

  void smf_selection_subscription_data_retrieval_handler(
      const std::string& supi, const response& response,
      std::string supported_features    = {},
      oai::model::common::PlmnId PlmnId = {});

  void subscription_creation_handler(
      const std::string& supi,
      const oai::model::udm::SdmSubscription& sdmSubscription,
      const response& response);

  void stop();

 private:
  std::string m_address;
  uint32_t m_port;
  http2 server;
  udm_app* m_udm_app;
  bool running_server;
};

#endif
