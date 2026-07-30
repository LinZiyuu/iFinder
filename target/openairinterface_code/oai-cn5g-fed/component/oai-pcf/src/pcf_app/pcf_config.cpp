/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "pcf_config.hpp"

oai::config::pcf::pcf_config::pcf_config(
    const std::string& config_path, bool log_stdout, bool log_rot_file)
    : config(
          config_path, oai::config::PCF_CONFIG_NAME, log_stdout, log_rot_file) {
  m_used_sbi_values = {
      oai::config::PCF_CONFIG_NAME, oai::config::NRF_CONFIG_NAME};
  m_used_config_values = {
      oai::config::LOG_LEVEL_CONFIG_NAME, oai::config::REGISTER_NF_CONFIG_NAME,
      oai::config::NF_LIST_CONFIG_NAME,   oai::config::PCF_CONFIG_NAME,
      oai::config::NF_CONFIG_HTTP_NAME,   oai::config::DATABASE_CONFIG};

  auto pcf = std::make_shared<pcf_config_type>(
      PCF_CONFIG_NAME, "oai-pcf",
      sbi_interface("SBI", "oai-pcf", 80, "v1", "eth0"), false,
      policy_config(
          DEFAULT_POLICY_DECISIONS_PATH, DEFAULT_PCC_RULES_PATH,
          DEFAULT_TRAFFIC_RULES_PATH, DEFAULT_QOS_DATA_PATH));

  auto nrf = std::make_shared<nf>(
      NRF_CONFIG_NAME, "oai-nrf",
      sbi_interface("SBI", "oai-nrf", 80, "v1", ""));

  add_nf(PCF_CONFIG_NAME, pcf);
  add_nf(NRF_CONFIG_NAME, nrf);
}

const oai::config::pcf::policy_config&
oai::config::pcf::pcf_config::get_pcf_policy() const {
  return std::dynamic_pointer_cast<pcf_config_type>(get_local())
      ->get_policy_config();
}

bool oai::config::pcf::pcf_config::use_db_policy_storage() const {
  return std::dynamic_pointer_cast<pcf_config_type>(get_local())
      ->enable_policy_provisioning_api();
}
