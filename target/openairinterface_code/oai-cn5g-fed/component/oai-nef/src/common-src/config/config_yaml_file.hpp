/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include "config.hpp"
#include "config_types.hpp"

#include <string>
#include <yaml-cpp/yaml.h>
#include <iostream>

namespace oai::config {

class yaml_file_iface {
  /**
   * Reads configuration from YAML file and loads it into the configuration
   * @throw std::runtime_error when file does not exist or could not be parsed
   * @param filepath filepath to load configuration from
   * @param config config object to load into
   */
  virtual void read_from_file(
      const std::string& file_path, config_iface& config) = 0;
};

class yaml_file : public yaml_file_iface {
 public:
  explicit yaml_file() = default;

  void read_from_file(
      const std::string& file_path, config_iface& config) override;

 private:
  template<class T>
  static bool convert_type(
      const std::string& conf, const YAML::Node& node, config_iface& config);
};

}  // namespace oai::config
