/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "udr_config.hpp"

#include "config.hpp"
#include "logger.hpp"

namespace oai::udr::config {

//------------------------------------------------------------------------------
udr_config::udr_config()
    : db_conf(), instance(), udr_name(), pid_dir(), nudr() {
  nudr.api_version = "v1";
  db_type          = DB_TYPE_MYSQL;
  use_http2        = false;
  register_nrf     = false;
  log_level        = spdlog::level::debug;
  http_request_timeout =
      oai::config::NF_CONFIG_HTTP_REQUEST_TIMEOUT_DEFAULT_VALUE;
}

//------------------------------------------------------------------------------
udr_config::~udr_config() {}

}  // namespace oai::udr::config
