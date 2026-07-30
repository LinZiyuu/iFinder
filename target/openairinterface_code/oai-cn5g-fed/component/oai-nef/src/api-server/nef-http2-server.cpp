/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "nef-http2-server.h"

#include <boost/algorithm/string.hpp>
#include <boost/thread.hpp>
#include <boost/thread/future.hpp>
#include <iostream>
#include <nlohmann/json.hpp>
#include <regex>
#include <string>

#include "3gpp_29.500.h"
#include "logger.hpp"
#include "nef_config.hpp"
#include "string.hpp"

using namespace nghttp2::asio_http2;
using namespace nghttp2::asio_http2::server;
// using namespace oai::nef::model;

extern nef_config nef_cfg;

//------------------------------------------------------------------------------
void nef_http2_server::start() {
  boost::system::error_code ec;

  Logger::nef_app().info("HTTP2 server started");

  // TODO

  if (server.listen_and_serve(ec, m_address, std::to_string(m_port))) {
    std::cerr << "HTTP Server error: " << ec.message() << std::endl;
  }
}

//------------------------------------------------------------------------------
void nef_http2_server::stop() {
  server.stop();
}
