/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "udm_config_yaml.hpp"

#include <boost/algorithm/string.hpp>

#include "conversions.hpp"
#include "logger.hpp"

namespace oai::config {

//------------------------------------------------------------------------------
subscriber_profile::subscriber_profile() {}

subscriber_profile::subscriber_profile(
    const uint8_t& protection_scheme,
    const std::string& home_network_public_key,
    const std::string& home_network_private_key,
    const std::string& home_network_public_key_id)
    : subscriber_profile() {
  m_protection_scheme =
      int_config_value(UDM_CONFIG_PROTECTION_SCHEME, protection_scheme);
  m_home_network_public_key = string_config_value(
      UDM_CONFIG_HOME_NETWORK_PUBLIC_KEY, home_network_public_key);
  m_home_network_private_key = string_config_value(
      UDM_CONFIG_HOME_NETWORK_PRIVATE_KEY, home_network_private_key);
  m_home_network_public_key_id = string_config_value(
      UDM_CONFIG_HOME_NETWORK_PUBLIC_KEY_ID, home_network_public_key_id);
}

//------------------------------------------------------------------------------
void subscriber_profile::from_yaml(const YAML::Node& node) {
  if (node[UDM_CONFIG_PROTECTION_SCHEME]) {
    m_protection_scheme.from_yaml(node[UDM_CONFIG_PROTECTION_SCHEME]);
  }
  if (node[UDM_CONFIG_HOME_NETWORK_PUBLIC_KEY]) {
    m_home_network_public_key.from_yaml(
        node[UDM_CONFIG_HOME_NETWORK_PUBLIC_KEY]);
  }
  if (node[UDM_CONFIG_HOME_NETWORK_PRIVATE_KEY]) {
    m_home_network_private_key.from_yaml(
        node[UDM_CONFIG_HOME_NETWORK_PRIVATE_KEY]);
  }
  if (node[UDM_CONFIG_HOME_NETWORK_PUBLIC_KEY_ID]) {
    m_home_network_public_key_id.from_yaml(
        node[UDM_CONFIG_HOME_NETWORK_PUBLIC_KEY_ID]);
  }
}

//------------------------------------------------------------------------------
std::string subscriber_profile::to_string(const std::string& indent) const {
  std::string out;
  unsigned int inner_width = get_inner_width(indent.length());

  out.append(indent).append(fmt::format(
      BASE_FORMATTER, INNER_LIST_ELEM, UDM_CONFIG_PROTECTION_SCHEME_LABEL,
      inner_width, m_protection_scheme.get_value()));

  out.append(indent).append(fmt::format(
      BASE_FORMATTER, EMPTY_LIST_ELEM, UDM_CONFIG_HOME_NETWORK_PUBLIC_KEY_LABEL,
      inner_width, m_home_network_public_key.get_value()));

  out.append(indent).append(fmt::format(
      BASE_FORMATTER, EMPTY_LIST_ELEM,
      UDM_CONFIG_HOME_NETWORK_PRIVATE_KEY_LABEL, inner_width,
      m_home_network_private_key.get_value()));

  out.append(indent).append(fmt::format(
      BASE_FORMATTER, EMPTY_LIST_ELEM,
      UDM_CONFIG_HOME_NETWORK_PUBLIC_KEY_ID_LABEL, inner_width,
      m_home_network_public_key_id.get_value()));

  return out;
}

//------------------------------------------------------------------------------
uint8_t subscriber_profile::get_protection_scheme() const {
  return m_protection_scheme.get_value();
}

//------------------------------------------------------------------------------
std::string subscriber_profile::get_home_network_public_key() const {
  return m_home_network_public_key.get_value();
}

//------------------------------------------------------------------------------
std::string subscriber_profile::get_home_network_private_key() const {
  return m_home_network_private_key.get_value();
}

//------------------------------------------------------------------------------
std::string subscriber_profile::get_home_network_public_key_id() const {
  return m_home_network_public_key_id.get_value();
}

//------------------------------------------------------------------------------
void subscriber_profile::validate() {
  if (!m_set) return;
  m_protection_scheme.validate();
  m_home_network_public_key.validate();
  m_home_network_private_key.validate();
  m_home_network_public_key_id.validate();
}

//------------------------------------------------------------------------------
udm::udm(
    const std::string& name, const std::string& host, const sbi_interface& sbi)
    : nf(name, host, sbi) {}

void udm::from_yaml(const YAML::Node& node) {
  nf::from_yaml(node);

  // Load UDM specified parameter
  for (const auto& elem : node) {
    auto key = elem.first.as<std::string>();

    if (key == UDM_CONFIG_INSTANCE_ID) {
      m_instance_id.from_yaml(elem.second);
    }

    if (key == UDM_CONFIG_PID_DIRECTORY) {
      m_pid_directory.from_yaml(elem.second);
    }

    if (key == UDM_CONFIG_UDM_NAME) {
      m_udm_name.from_yaml(elem.second);
    }

    if (key == UDM_CONFIG_SUBSCRIBER_PROFILE_LIST) {
      if (!elem.second.IsSequence()) {
        Logger::udm_app().warn("Could not parse %s", key);
      } else {
        for (int i = 0; i < elem.second.size(); i++) {
          subscriber_profile sp;
          sp.from_yaml(elem.second[i]);
          m_subscriber_profile_list.push_back(sp);
        }
      }
    }
  }
}

//------------------------------------------------------------------------------
std::string udm::to_string(const std::string& indent) const {
  std::string out;
  std::string inner_indent = indent + indent;
  unsigned int inner_width = get_inner_width(inner_indent.length());

  out.append(indent).append(nf::to_string(indent));

  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, OUTER_LIST_ELEM, UDM_CONFIG_INSTANCE_ID_LABEL,
          inner_width, m_instance_id.get_value()));

  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, OUTER_LIST_ELEM, UDM_CONFIG_PID_DIRECTORY_LABEL,
          inner_width, m_pid_directory.get_value()));

  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, OUTER_LIST_ELEM, UDM_CONFIG_UDM_NAME_LABEL,
          inner_width, m_udm_name.get_value()));

  if (m_subscriber_profile_list.empty()) return out;

  out.append(inner_indent)
      .append(fmt::format(
          "{} {}\n", OUTER_LIST_ELEM,
          UDM_CONFIG_SUBSCRIBER_PROFILE_LIST_LABEL));
  for (const auto& i : m_subscriber_profile_list)
    out.append(i.to_string(inner_indent + indent));

  return out;
}

//------------------------------------------------------------------------------
const uint32_t udm::get_instance_id() const {
  return m_instance_id.get_value();
}
//------------------------------------------------------------------------------
const std::string udm::get_pid_directory() const {
  return m_pid_directory.get_value();
}
//------------------------------------------------------------------------------
const std::string udm::get_udm_name() const {
  return m_udm_name.get_value();
}

const std::vector<subscriber_profile> udm::get_subscriber_profile_list() const {
  return m_subscriber_profile_list;
}

//------------------------------------------------------------------------------
udm_config_yaml::udm_config_yaml(
    const std::string& config_path, bool log_stdout, bool log_rot_file)
    : oai::config::config(
          config_path, oai::config::UDM_CONFIG_NAME, log_stdout, log_rot_file) {
  m_used_sbi_values = {
      oai::config::UDM_CONFIG_NAME, oai::config::UDR_CONFIG_NAME,
      oai::config::NRF_CONFIG_NAME};
  m_used_config_values = {oai::config::LOG_LEVEL_CONFIG_NAME,
                          oai::config::REGISTER_NF_CONFIG_NAME,
                          oai::config::NF_CONFIG_HTTP_NAME,
                          oai::config::NF_CONFIG_HTTP_REQUEST_TIMEOUT,
                          oai::config::NF_LIST_CONFIG_NAME,
                          oai::config::UDM_CONFIG_NAME};

  // TODO with NF_Type and switch
  // TODO: Still we need to add default NFs even we don't use this in all_in_one
  // use case
  auto m_udm = std::make_shared<udm>(
      "UDM", "oai-udm", sbi_interface("SBI", "oai-udm", 80, "v1", "eth0"));
  add_nf(oai::config::UDM_CONFIG_NAME, m_udm);

  auto m_udr = std::make_shared<nf>(
      "UDR", "oai-udr", sbi_interface("SBI", "oai-udr", 80, "v1", "eth0"));
  add_nf(oai::config::UDR_CONFIG_NAME, m_udr);

  auto m_nrf = std::make_shared<nf>(
      "NRF", "oai-nrf", sbi_interface("SBI", "oai-nrf", 80, "v1", "eth0"));
  add_nf(oai::config::NRF_CONFIG_NAME, m_nrf);

  update_used_nfs();
}

//------------------------------------------------------------------------------
udm_config_yaml::~udm_config_yaml() {}

void udm_config_yaml::pre_process() {
  // Process configuration information to display only the appropriate
  // information
  // TODO: discover UDR via NRF
  std::shared_ptr<nf> udr = get_nf(oai::config::UDR_CONFIG_NAME);
  udr->set_config();
}

//------------------------------------------------------------------------------
void udm_config_yaml::to_udm_config(oai::udm::config::udm_config& cfg) {
  std::shared_ptr<udm> udm_local = std::static_pointer_cast<udm>(get_local());
  cfg.instance                   = udm_local->get_instance_id();
  cfg.pid_dir                    = udm_local->get_pid_directory();
  cfg.udm_name                   = udm_local->get_udm_name();
  cfg.log_level                  = spdlog::level::from_str(log_level());
  cfg.register_nrf               = register_nrf();
  cfg.http_request_timeout       = get_http_request_timeout();

  if (get_http_version() == 2) cfg.use_http2 = true;

  cfg.sbi.api_version = local().get_sbi().get_api_version();
  cfg.sbi.port        = local().get_sbi().get_port();
  cfg.sbi.addr4       = local().get_sbi().get_addr4();
  cfg.sbi.if_name     = local().get_sbi().get_if_name();

  if (get_nf(oai::config::NRF_CONFIG_NAME)) {
    cfg.nrf_addr.api_version =
        get_nf(oai::config::NRF_CONFIG_NAME)->get_sbi().get_api_version();
    cfg.nrf_addr.uri_root = get_nf(oai::config::NRF_CONFIG_NAME)->get_url();
  }
  if (get_nf(oai::config::UDR_CONFIG_NAME)) {
    cfg.udr_addr.api_version =
        get_nf(oai::config::UDR_CONFIG_NAME)->get_sbi().get_api_version();
    cfg.udr_addr.uri_root = get_nf(oai::config::UDR_CONFIG_NAME)->get_url();
  }

  for (const auto& profile : udm_local->get_subscriber_profile_list()) {
    subscriber_profile_t sp;
    sp.protection_scheme          = profile.get_protection_scheme();
    sp.home_network_public_key    = profile.get_home_network_public_key();
    sp.home_network_private_key   = profile.get_home_network_private_key();
    sp.home_network_public_key_id = profile.get_home_network_public_key_id();
    cfg.subscriber_profiles.push_back(sp);
  }
}
}  // namespace oai::config
