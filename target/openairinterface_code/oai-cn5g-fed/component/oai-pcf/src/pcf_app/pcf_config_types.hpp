/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once
#include "config_types.hpp"

namespace oai::config::pcf {

class policy_config : public config_type {
 private:
  string_config_value m_pcc_rules_path;
  string_config_value m_policy_decisions_path;
  string_config_value m_traffic_rules_path;
  string_config_value m_qos_data_path;

 public:
  explicit policy_config(
      const std::string& policy_decisions_path,
      const std::string& pcc_rules_path, const std::string& traffic_rules_path,
      const std::string& qos_data_path);

  void from_yaml(const YAML::Node& node) override;

  [[nodiscard]] std::string to_string(const std::string& indent) const override;
  [[nodiscard]] const std::string& get_pcc_rules_path() const;
  [[nodiscard]] const std::string& get_policy_decisions_path() const;
  [[nodiscard]] const std::string& get_traffic_rules_path() const;
  [[nodiscard]] const std::string& get_qos_data_path() const;
};

class pcf_config_type : public nf {
 private:
  option_config_value m_enable_policy_provisioning_api;
  policy_config m_policy_config;

 public:
  explicit pcf_config_type(
      const std::string& name, const std::string& host,
      const sbi_interface& sbi, bool enable_policy_provisioning_api,
      const policy_config& policy);

  void from_yaml(const YAML::Node& node) override;

  [[nodiscard]] std::string to_string(const std::string& indent) const override;

  void validate() override;

  [[nodiscard]] bool enable_policy_provisioning_api() const;
  [[nodiscard]] const policy_config& get_policy_config() const;
};

}  // namespace oai::config::pcf