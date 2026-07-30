/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _UDR_CONFIG_H_
#define _UDR_CONFIG_H_

#include <string>

#include "udr.h"
#include "logger.hpp"
#include "sbi_helper.hpp"

namespace oai::udr::config {

typedef struct {
  std::string server;
  uint32_t port;
  std::string user;
  std::string pass;
  std::string db_name;
  uint32_t connection_timeout;
} db_conf_t;

class udr_config {
 public:
  udr_config();
  ~udr_config();

  unsigned int instance;
  std::string pid_dir;
  std::string udr_name;
  spdlog::level::level_enum log_level;
  oai::common::sbi::interface_cfg_t nudr;
  oai::common::sbi::nf_addr_t nrf_addr;
  bool register_nrf;
  bool use_http2;
  uint32_t http_request_timeout;
  db_conf_t db_conf;
  db_type_t db_type;
};
}  // namespace oai::udr::config

#endif
