/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_AUSF_HTTP2_SERVER_SEEN
#define FILE_AUSF_HTTP2_SERVER_SEEN

#include <nghttp2/asio_http2_server.h>

#include "AuthenticationInfo.h"
#include "ConfirmationData.h"
#include "DeregistrationInfo.h"
#include "EapSession.h"
#include "RgAuthenticationInfo.h"
#include "ausf_app.hpp"
#include "conversions.hpp"

using namespace nghttp2::asio_http2;
using namespace nghttp2::asio_http2::server;
using namespace oai::model::ausf;
using namespace oai::ausf::app;

class ausf_http2_server {
 public:
  ausf_http2_server(std::string addr, uint32_t port, ausf_app* ausf_app_inst)
      : m_address(addr),
        m_port(port),
        server(),
        m_ausf_app(ausf_app_inst),
        running_server(false) {}
  void start();
  void init(size_t thr) {}

  void eap_auth_method_handler(
      const std::string& auth_ctx_id, const EapSession& eap_session,
      const response& response);
  void rg_authentications_post_handler(
      const RgAuthenticationInfo& rg_authentication_info,
      const response& response);
  void ue_authentications_auth_ctx_id5g_aka_confirmation_put_handler(
      const std::string& authCtxId, const ConfirmationData& confirmation_data,
      const response& response);
  void ue_authentications_deregister_post_handler(
      const DeregistrationInfo& deregistration_info, const response& response);
  void ue_authentications_post_handler(
      const AuthenticationInfo& authentication_info, const response& response);

  void stop();

 private:
  std::string m_address;
  uint32_t m_port;
  http2 server;
  ausf_app* m_ausf_app;
  bool running_server;
};

#endif
