/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _UDM_CONFIG_H_
#define _UDM_CONFIG_H_

#include "udm.h"
#include "udm_config.hpp"

using namespace oai::common::sbi;
namespace oai::udm::config {

class udm_config {
 public:
  udm_config();
  ~udm_config();

  unsigned int instance;
  std::string pid_dir;
  std::string udm_name;
  spdlog::level::level_enum log_level;

  interface_cfg_t sbi;
  nf_addr_t udr_addr;
  nf_addr_t nrf_addr;

  bool register_nrf;
  bool use_http2;
  uint32_t http_request_timeout;

  std::vector<subscriber_profile_t> subscriber_profiles;
};

}  // namespace oai::udm::config

#endif
