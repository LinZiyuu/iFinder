/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _LMF_CONFIG_H_
#define _LMF_CONFIG_H_

#include <chrono>
#include <string>

#include "logger_base.hpp"
#include "sbi_helper.hpp"

constexpr auto LMF_CONFIG_OPTION_YES_STR = "Yes";
constexpr auto LMF_CONFIG_OPTION_NO_STR  = "No";

namespace oai::lmf::config {
using namespace oai::common::sbi;
class lmf_config {
 public:
  lmf_config();
  virtual ~lmf_config(){};

  unsigned int instance               = 1;
  std::string pid_dir                 = "/var/run";
  std::string lmf_name                = "OAI_LMF";
  spdlog::level::level_enum log_level = spdlog::level::debug;

  unsigned http_threads_count = 8;
  unsigned gnb_id_bits_count  = 28;
  bool determine_num_gnb      = false;
  unsigned num_gnb            = 1;
  std::chrono::milliseconds trp_info_wait_ms{10000};
  std::chrono::milliseconds positioning_wait_ms{10000};
  std::chrono::milliseconds measurement_wait_ms{10000};

  interface_cfg_t sbi;
  nf_addr_t amf_addr;
  nf_addr_t nrf_addr;

  bool register_nrf;
  bool request_trp_info;
  bool use_http2;
  uint32_t http_request_timeout;
};

}  // namespace oai::lmf::config

extern oai::lmf::config::lmf_config lmf_cfg;

#endif
