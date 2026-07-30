/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _AUSF_CONFIG_H_
#define _AUSF_CONFIG_H_

#include "ausf.h"
#include "logger.hpp"

using namespace oai::common::sbi;

namespace oai::config {

class ausf_config {
 public:
  ausf_config();
  ~ausf_config();

  /*
   * Get the root URI of UDM UE Authentication API
   * @param void
   * @return URI in string format
   */
  std::string get_udm_ueau_api_root() const;

  /*
   * Get the URI of UDM to generate authentication data for the UE
   * @param [const std::string&] supi: UE SUPI
   * @return URI in string format
   */
  std::string get_udm_ueau_generate_auth_data_uri(
      const std::string& supi) const;

  /*
   * Get the URI of UDM to create a new confirmation event
   * @param [const std::string&] supi: UE SUPI
   * @return URI in string format
   */
  std::string get_udm_ueau_confirm_auth_uri(const std::string& supi) const;

  unsigned int instance;
  std::string pid_dir;
  std::string ausf_name;
  spdlog::level::level_enum log_level;

  interface_cfg_t sbi;
  nf_addr_t udm_addr;
  nf_addr_t nrf_addr;

  bool register_nrf;
  uint8_t http_version;
  uint32_t http_request_timeout;
};

}  // namespace oai::config

#endif
