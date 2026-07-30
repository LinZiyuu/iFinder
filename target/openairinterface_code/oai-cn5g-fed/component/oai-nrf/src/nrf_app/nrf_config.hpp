/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include "config.hpp"
#include "nrf_config_types.hpp"

namespace oai::config::nrf {

class nrf_config : public oai::config::config {
 public:
  // Stefan: we should get rid of this instance things (see PCF)
  unsigned int instance = 0;
  explicit nrf_config(
      const std::string& config_path, bool log_stdout, bool log_rot_file)
      : config(config_path, NRF_CONFIG_NAME, log_stdout, log_rot_file) {
    m_used_config_values = {
        LOG_LEVEL_CONFIG_NAME, NF_LIST_CONFIG_NAME, NF_CONFIG_HTTP_NAME,
        NRF_CONFIG_NAME};
    m_used_sbi_values = {NRF_CONFIG_NAME};

    m_register_nrf_feature.unset_config();

    auto nrf = std::make_shared<nrf_config_type>(
        NRF_CONFIG_NAME, "oai-nrf",
        sbi_interface("SBI", "oai-nrf", 80, "v1", "eth0"));
    add_nf(NRF_CONFIG_NAME, nrf);
  };

  std::shared_ptr<nrf_config_type> nrf() const {
    return std::static_pointer_cast<nrf_config_type>(get_local());
  };
};
}  // namespace oai::config::nrf
