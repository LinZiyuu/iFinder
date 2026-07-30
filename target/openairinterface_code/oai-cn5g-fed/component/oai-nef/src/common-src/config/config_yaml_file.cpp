/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "config_yaml_file.hpp"
#include "logger_base.hpp"

using namespace oai::logger;

void oai::config::yaml_file::read_from_file(
    const std::string& file_path, oai::config::config_iface& config) {
  try {
    YAML::Node node = YAML::LoadFile(file_path);
    for (const auto& elem : node) {
      bool success;
      auto key = elem.first.as<std::string>();
      if (elem.second.IsScalar()) {
        success = convert_type<uint8_config_value>(key, elem.second, config);
        if (!success) {
          success = convert_type<option_config_value>(key, elem.second, config);
        }
        if (!success) {
          success = convert_type<string_config_value>(key, elem.second, config);
        }
      } else {
        success = convert_type<sbi_interface>(key, elem.second, config);
        if (!success) {
          success = convert_type<local_sbi_interface>(key, elem.second, config);
        }
        if (!success) {
          success = convert_type<local_interface>(key, elem.second, config);
        }
      }

      if (!success) {
        logger_registry::get_logger(LOGGER_NAME)
            .warn("Could not parse YAML element: %s", key);
      }
    }
  } catch (YAML::BadFile& ex) {
    logger_registry::get_logger(LOGGER_NAME)
        .error(
            "Could not read YAML configuration file, please ensure that it "
            "exists: %s",
            ex.what());
    throw std::runtime_error(ex.what());
  } catch (std::exception& ex) {
    logger_registry::get_logger(LOGGER_NAME)
        .error("Could not parse YAML configuration file: %s", ex.what());
    throw std::runtime_error(ex.what());
  }
}

template<class T>
bool oai::config::yaml_file::convert_type(
    const std::string& key, const YAML::Node& node, config_iface& config) {
  try {
    T conf_val{node};
    std::unique_ptr<config_type> conf = std::make_unique<T>(conf_val);
    config.set_configuration(key, std::move(conf));
    return true;

  } catch (std::exception&) {
    return false;
  }
}
