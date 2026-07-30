/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "config.hpp"
#include "if.hpp"

#include <fmt/format.h>
#include <stdexcept>
#include <regex>

using namespace oai::config;

lttng_configuration::lttng_configuration(const std::string& config_path)
    : m_lttng("lttng_config") {
  m_config_path = config_path;
}

void lttng_configuration::read_from_file() {
  YAML::Node node = YAML::LoadFile(m_config_path);
  for (const auto& elem : node) {
    auto key = elem.first.as<std::string>();
    if (key != "lttng") continue;

    m_lttng.from_yaml(elem.second);
  }
}

bool lttng_configuration::is_lttng_active() const {
  return m_lttng.is_lttng_active();
}

std::string lttng_configuration::get_lttng_log_level() {
  return m_lttng.get_lttng_log_level();
}

config::config(
    const std::string& config_path, const std::string& nf_name, bool log_stdout,
    bool log_rot_file)
    : m_register_nrf_feature(REGISTER_NF_CONFIG_NAME, nf_name, false),
      m_log_level_feature(LOG_LEVEL_CONFIG_NAME, nf_name, std::string("info")),
      m_tls_config(),
      m_http_version(),
      m_http_request_timeout(),
      m_database(DATABASE_CONFIG) {
  logger::logger_registry::register_logger(
      nf_name, LOGGER_NAME, log_stdout, log_rot_file);

  m_log_level_feature.set_validation_regex(LOG_LVL_VALIDATOR_REGEX);

  m_config_path = config_path;
  m_nf_name     = nf_name;
}

void config::read_from_file(const std::string& file_path) {
  try {
    YAML::Node node = YAML::LoadFile(file_path);
    for (const auto& elem : node) {
      auto key = elem.first.as<std::string>();
      if (m_used_config_values.find(key) == m_used_config_values.end()) {
        continue;
      }
      try {
        if (key == LOG_LEVEL_CONFIG_NAME) {
          m_log_level_feature.from_yaml(elem.second);
        } else if (key == REGISTER_NF_CONFIG_NAME) {
          m_register_nrf_feature.from_yaml(elem.second);
        } else if (key == NF_CONFIG_HTTP_NAME) {
          m_http_version.from_yaml(elem.second);
        } else if (key == NF_CONFIG_TLS_NAME) {
          m_tls_config.from_yaml(elem.second);
        } else if (key == NF_CONFIG_HTTP_REQUEST_TIMEOUT) {
          m_http_request_timeout.from_yaml(elem.second);
        } else if (key == m_nf_name) {
          const auto nf_ptr = m_nf_map.find(m_nf_name);
          if (nf_ptr == m_nf_map.end()) {
            logger::logger_registry::get_logger(LOGGER_NAME)
                .debug("Unknown NF %s in configuration. Ignored", m_nf_name);
            continue;
          }

          try {
            nf_ptr->second->from_yaml(elem.second);
          } catch (std::exception& e) {
            logger::logger_registry::get_logger(LOGGER_NAME)
                .warn("Could not parse %s: %s", m_nf_name, e.what());
          }
        } else if (key == NF_LIST_CONFIG_NAME) {
          for (auto yaml_nf : elem.second) {
            auto nf_name = yaml_nf.first.as<std::string>();

            const auto nf_ptr = m_nf_map.find(nf_name);
            if (nf_ptr == m_nf_map.end()) {
              logger::logger_registry::get_logger(LOGGER_NAME)
                  .debug("Unknown NF %s in configuration. Ignored", nf_name);
              continue;
            }
            if (m_used_sbi_values.find(nf_name) == m_used_sbi_values.end()) {
              // we unset the values that are not used by this NF -> they are
              // not validated and not printed
              nf_ptr->second->m_set = false;
              continue;
            }
            try {
              nf_ptr->second->from_yaml(yaml_nf.second);
            } catch (std::exception& e) {
              logger::logger_registry::get_logger(LOGGER_NAME)
                  .warn("Could not parse %s: %s", nf_name, e.what());
            }
          }
        } else if (key == DATABASE_CONFIG) {  // TODO: Don't need to do this if
                                              // we drop the support for Minimal
                                              // scenario
          m_database.from_yaml(elem.second);
        } else if (key == DNNS_CONFIG_NAME) {
          // remove default DNNs
          m_dnns.clear();

          for (const auto& yaml_dnn : elem.second) {
            dnn_config cfg("default", "IPv4", "12.1.1.0/24", "");
            cfg.from_yaml(yaml_dnn);
            m_dnns.push_back(cfg);
          }
        }
      } catch (std::exception& e) {
        logger::logger_registry::get_logger(LOGGER_NAME)
            .warn("Could not parse %s: %s", key, e.what());
      }
    }
  } catch (YAML::BadFile& ex) {
    logger::logger_registry::get_logger(LOGGER_NAME)
        .error(
            "Could not read YAML configuration file, please ensure that it "
            "exists: %s",
            ex.what());
    throw std::runtime_error(ex.what());
  } catch (std::exception& ex) {
    logger::logger_registry::get_logger(LOGGER_NAME)
        .error("Could not parse YAML configuration file: %s", ex.what());
    throw std::runtime_error(ex.what());
  }

  update_used_nfs();
}

void config::to_json(nlohmann::json& json_data) {
  json_data[m_http_version.get_config_name()] = m_http_version.to_json();
  json_data[m_log_level_feature.get_config_name()] =
      m_log_level_feature.to_json();
  json_data[m_register_nrf_feature.get_config_name()] =
      m_register_nrf_feature.to_json();
  json_data[m_tls_config.get_config_name()] = m_tls_config.to_json();
  json_data[m_http_request_timeout.get_config_name()] =
      m_http_request_timeout.to_json();
  if (m_database.is_set()) {
    json_data[m_database.get_config_name()] = m_database.to_json();
  }
}

bool config::from_json(const nlohmann::json& json_data) {
  try {
    if (json_data.find(m_http_version.get_config_name()) != json_data.end()) {
      m_http_version.from_json(json_data[m_http_version.get_config_name()]);
    }

    if (json_data.find(m_log_level_feature.get_config_name()) !=
        json_data.end()) {
      m_log_level_feature.from_json(
          json_data[m_log_level_feature.get_config_name()]);
    }
    if (json_data.find(m_register_nrf_feature.get_config_name()) !=
        json_data.end()) {
      m_register_nrf_feature.from_json(
          json_data[m_register_nrf_feature.get_config_name()]);
    }

    if (json_data.find(m_tls_config.get_config_name()) != json_data.end()) {
      m_tls_config.from_json(json_data[m_tls_config.get_config_name()]);
    }

    if (json_data.find(m_http_request_timeout.get_config_name()) !=
        json_data.end()) {
      m_http_request_timeout.from_json(
          json_data[m_http_request_timeout.get_config_name()]);
    }

  } catch (nlohmann::detail::exception& e) {
    // TODO:
  } catch (std::exception& e) {
    // TODO:
  }
  return false;
}

bool config::validate() {
  std::shared_lock lock(m_config_mutex);
  bool success = true;

  success &= safe_validate_field(m_log_level_feature);
  // we set log level here to not print debug here, but first debug message is
  // printed
  if (success) {
    logger::logger_registry::set_level(spdlog::level::from_str(log_level()));
  }
  success &= safe_validate_field(m_register_nrf_feature);
  success &= safe_validate_field(m_http_version);
  success &= safe_validate_field(m_http_request_timeout);
  for (auto& nf : m_nf_map) {
    success &= safe_validate_field(*nf.second);
  }
  for (auto& dnn : m_dnns) {
    success &= safe_validate_field(dnn);
  }

  success &= safe_validate_field(m_database);

  return success;
}

bool config::safe_validate_field(config_type& config) {
  try {
    logger::logger_registry::get_logger(LOGGER_NAME)
        .debug("Validating configuration of %s", config.get_config_name());
    config.validate();
    return true;
  } catch (std::exception& e) {
    logger::logger_registry::get_logger(LOGGER_NAME)
        .error(
            "Validation of %s not successful: %s", config.get_config_name(),
            e.what());
    return false;
  }
}

std::string config::to_string() const {
  std::shared_lock lock(m_config_mutex);

  std::string base_conf_out;
  std::string support_features_out;
  std::string sbi_out;
  std::string local_iface_out;
  std::string others_out;

  std::string out;
  out.append("Basic Configuration:\n");
  std::string indent = fmt::format("{:<{}}", "", INDENT_WIDTH);
  out.append(m_log_level_feature.to_string(indent));
  out.append(m_register_nrf_feature.to_string(indent));
  out.append(m_http_version.to_string(indent));
  out.append(m_tls_config.to_string(indent));
  out.append(m_http_request_timeout.to_string(indent));

  out.append(m_local_nf->to_string(indent));
  if (m_database.is_set()) {
    out.append(indent).append("Database:\n");
    out.append(m_database.to_string(indent + indent));
  }
  if (!m_nf_map.empty()) {
    bool has_peer_nf = false;
    for (const auto& nf : m_nf_map) {
      if (nf.first != m_nf_name) {
        if (!has_peer_nf) {
          has_peer_nf = true;
          out.append("Peer NF Configuration:\n");
        }
        out.append(nf.second->to_string(indent));
      }
    }
  }

  if (!m_dnns.empty()) {
    out.append("DNNs:\n");
  }
  for (const auto& dnn : m_dnns) {
    if (dnn.is_set()) out.append(dnn.to_string(indent));
  }

  return out;
}

void config::display() const {
  logger::logger_registry::set_level(spdlog::level::info);
  std::stringstream ss(to_string());
  std::string line;

  logger::logger_registry::get_logger(LOGGER_NAME)
      .info("==== OPENAIRINTERFACE %s v%s ====", m_nf_name, PACKAGE_VERSION);

  while (std::getline(ss, line)) {
    logger::logger_registry::get_logger(LOGGER_NAME).info(line);
  }
  logger::logger_registry::set_level(spdlog::level::from_str(log_level()));
}

bool config::init() {
  try {
    logger::logger_registry::get_logger(LOGGER_NAME)
        .info("Reading NF configuration from %s", m_config_path);
    read_from_file(m_config_path);
  } catch (std::runtime_error& err) {
    return false;
  } catch (std::exception& e) {
    return false;
  }

  if (!validate()) {
    logger::logger_registry::get_logger(LOGGER_NAME)
        .error("Configuration validation not successful!");
    return false;
  }
  return true;
}

bool config::register_nrf() const {
  return m_register_nrf_feature.get_option();
}

const std::string& config::log_level() const {
  return m_log_level_feature.get_string();
}

bool config::enable_tls() const {
  return m_tls_config.enable_tls();
}

const tls_config& config::get_tls_config() const {
  return m_tls_config;
}

const nf& config::local() const {
  return *m_local_nf;
}

std::shared_ptr<nf> config::get_local() const {
  return m_local_nf;
}

std::shared_ptr<nf> config::get_nf(const std::string& nf_name) const {
  auto nf_ptr = m_nf_map.find(nf_name);
  if (nf_ptr == m_nf_map.end()) {
    return nullptr;
  }
  return nf_ptr->second;
}

class database_config& config::get_database_config() {
  return m_database;
}

const std::vector<dnn_config>& config::get_dnns() const {
  return m_dnns;
}

int config::get_http_version() const {
  if (m_http_version.get_http_version() == "1") {
    return 1;
  }
  if (m_http_version.get_http_version() == "1.1") {
    return 1;
  }
  if (m_http_version.get_http_version() == "2") {
    return 2;
  }
  // by default
  return 1;
}

uint32_t config::get_http_request_timeout() const {
  return m_http_request_timeout.get();
}

bool config::add_nf(
    const std::string& name, const std::shared_ptr<nf>& nf_ptr) {
  m_nf_map.insert(std::make_pair(name, nf_ptr));
  return true;
}

void config::update_used_nfs() {
  for (auto& nf : m_nf_map) {
    if (nf.first == m_nf_name) {
      m_local_nf = nf.second;
      m_local_nf->m_sbi.set_is_local_interface(
          true);  // TODO: to be updated with UPF
    } else {
      auto used_nf = m_used_sbi_values.find(nf.first);
      if (used_nf == m_used_sbi_values.end()) {
        nf.second->m_set = false;
      }
      // If we register to NRF; we unset all other NFs
      // Assume that each NF is discovered via NRF.
      if (register_nrf() && nf.first != NRF_CONFIG_NAME) {
        nf.second->m_set = false;
      }
      // If we do not register NRF, we unset NRF
      if (!register_nrf() && nf.first == NRF_CONFIG_NAME) {
        nf.second->m_set = false;
      }
    }
  }
}

std::string oai::config::get_value_formatter(int level) {
  {
    // TODO use this function everywhere, it is much simpler
    int indent_width        = level * INDENT_WIDTH;
    std::string base_indent = fmt::format("{:<{}}", "", indent_width);
    std::string indent_char =
        (level + 1) % 2 == 0 ? INNER_LIST_ELEM : OUTER_LIST_ELEM;

    unsigned int inner_width = COLUMN_WIDTH;
    if (base_indent.length() < COLUMN_WIDTH) {
      inner_width = COLUMN_WIDTH - base_indent.length();
    }
    return base_indent + indent_char + " {:.<" + std::to_string(inner_width) +
           "}: {}\n";
  }
}

std::string oai::config::get_title_formatter(int level) {
  {
    int indent_width        = level * INDENT_WIDTH;
    std::string base_indent = fmt::format("{:<{}}", "", indent_width);
    std::string indent_char =
        (level + 1) % 2 == 0 ? INNER_LIST_ELEM : OUTER_LIST_ELEM;
    return base_indent + indent_char + " {}\n";
  }
}
