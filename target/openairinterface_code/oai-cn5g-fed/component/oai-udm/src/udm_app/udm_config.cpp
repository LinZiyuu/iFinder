/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "udm_config.hpp"

#include "config.hpp"

namespace oai::udm::config {

//------------------------------------------------------------------------------
udm_config::udm_config() : instance(0), pid_dir(), udm_name(), sbi() {
  udr_addr.ipv4_addr.s_addr = INADDR_ANY;
  udr_addr.port             = 8080;  // HTTP2 by default
  udr_addr.api_version      = "v1";
  nrf_addr.ipv4_addr.s_addr = INADDR_ANY;
  nrf_addr.port             = 8080;  // HTTP2 by default
  nrf_addr.api_version      = "v1";
  use_http2                 = false;
  register_nrf              = false;
  log_level                 = spdlog::level::debug;
  http_request_timeout =
      oai::config::NF_CONFIG_HTTP_REQUEST_TIMEOUT_DEFAULT_VALUE;
}

//------------------------------------------------------------------------------
udm_config::~udm_config() {}
}  // namespace oai::udm::config
