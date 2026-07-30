/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "lmf_config.hpp"

#include "config.hpp"

namespace oai::lmf::config {

//------------------------------------------------------------------------------
lmf_config::lmf_config() : sbi() {
  use_http2        = false;
  register_nrf     = false;
  request_trp_info = false;
  http_request_timeout =
      oai::config::NF_CONFIG_HTTP_REQUEST_TIMEOUT_DEFAULT_VALUE;
}

}  // namespace oai::lmf::config
