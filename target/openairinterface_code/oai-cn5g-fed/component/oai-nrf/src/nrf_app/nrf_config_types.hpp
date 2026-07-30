/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include "config.hpp"

constexpr auto NRF_CONFIG_HEARTBEAT                   = "heartbeat";
constexpr auto NRF_CONFIG_HEARTBEAT_LABEL             = "Heartbeat";
constexpr auto NRF_CONFIG_SUSPENDED_NF_INTERVAL       = "suspended_nf_interval";
constexpr auto NRF_CONFIG_SUSPENDED_NF_INTERVAL_LABEL = "Suspended NF Interval";

namespace oai::config::nrf {

class nrf_config_type : public oai::config::nf {
  friend class nrf_config;

 private:
  int_config_value m_heartbeat;
  int_config_value m_suspended_nf_interval;

 public:
  explicit nrf_config_type(
      const std::string& name, const std::string& host,
      const sbi_interface& sbi);
  void from_yaml(const YAML::Node& node) override;
  nlohmann::json to_json() override;
  bool from_json(const nlohmann::json& json_data) override;

  [[nodiscard]] std::string to_string(const std::string& indent) const override;

  void validate() override;

  [[nodiscard]] uint16_t get_heartbeat() const;
  void set_heartbeat(uint16_t);

  [[nodiscard]] uint16_t get_suspended_nf_interval() const;
  void set_suspended_nf_interval(uint16_t);
};

}  // namespace oai::config::nrf
