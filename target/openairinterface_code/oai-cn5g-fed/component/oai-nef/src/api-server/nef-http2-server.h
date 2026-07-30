/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_NEF_HTTP2_SERVER_SEEN
#define FILE_NEF_HTTP2_SERVER_SEEN

#include "conversions.hpp"

//#include "nef.h"
#include <nghttp2/asio_http2_server.h>

#include "nef_app.hpp"
#include "uint_generator.hpp"

using namespace nghttp2::asio_http2;
using namespace nghttp2::asio_http2::server;
// using namespace oai::nef::model;
using namespace oai::nef::app;

class nef_http2_server {
 public:
  nef_http2_server(std::string addr, uint32_t port, nef_app* nef_app_inst)
      : m_address(addr), m_port(port), server(), m_nef_app(nef_app_inst) {}
  void start();
  void init(size_t thr) {}

  void stop();

 private:
  util::uint_generator<uint32_t> m_promise_id_generator;
  std::string m_address;
  uint32_t m_port;
  http2 server;
  nef_app* m_nef_app;

 protected:
  static uint64_t generate_promise_id() {
    return util::uint_uid_generator<uint64_t>::get_instance().get_uid();
  }
};

#endif
