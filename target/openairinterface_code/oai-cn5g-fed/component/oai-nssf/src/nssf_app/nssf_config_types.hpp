/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once
#include "config_types.hpp"

namespace oai::config::nssf {

class nssf_config_type : public nf {
 private:
  string_config_value m_slice_config_path;

 public:
  explicit nssf_config_type(
      const std::string& name, const std::string& host,
      const sbi_interface& sbi, const std::string& slice_cfg_path);

  void from_yaml(const YAML::Node& node) override;

  [[nodiscard]] std::string to_string(const std::string& indent) const override;

  void validate() override;

  [[nodiscard]] const std::string& get_slice_config_path() const;
};

}  // namespace oai::config::nssf
