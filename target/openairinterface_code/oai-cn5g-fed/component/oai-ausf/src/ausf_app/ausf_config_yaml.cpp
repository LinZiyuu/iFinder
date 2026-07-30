/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "ausf_config_yaml.hpp"

#include <boost/algorithm/string.hpp>

#include "conversions.hpp"
#include "logger.hpp"

namespace oai::config {

//------------------------------------------------------------------------------
ausf::ausf(
    const std::string& name, const std::string& host, const sbi_interface& sbi)
    : nf(name, host, sbi) {}

void ausf::from_yaml(const YAML::Node& node) {
  nf::from_yaml(node);

  // Load AUSF specified parameter
  for (const auto& elem : node) {
    auto key = elem.first.as<std::string>();

    if (key == AUSF_CONFIG_INSTANCE_ID) {
      m_instance_id.from_yaml(elem.second);
    }

    if (key == AUSF_CONFIG_PID_DIRECTORY) {
      m_pid_directory.from_yaml(elem.second);
    }

    if (key == AUSF_CONFIG_AUSF_NAME) {
      m_ausf_name.from_yaml(elem.second);
    }
  }
}

//------------------------------------------------------------------------------
std::string ausf::to_string(const std::string& indent) const {
  std::string out;
  std::string inner_indent = indent + indent;
  unsigned int inner_width = get_inner_width(inner_indent.length());

  out.append(indent).append(nf::to_string(indent));

  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, OUTER_LIST_ELEM, AUSF_CONFIG_INSTANCE_ID_LABEL,
          inner_width, m_instance_id.get_value()));

  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, OUTER_LIST_ELEM, AUSF_CONFIG_PID_DIRECTORY_LABEL,
          inner_width, m_pid_directory.get_value()));

  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, OUTER_LIST_ELEM, AUSF_CONFIG_AUSF_NAME_LABEL,
          inner_width, m_ausf_name.get_value()));

  return out;
}

//------------------------------------------------------------------------------
const uint32_t ausf::get_instance_id() const {
  return m_instance_id.get_value();
}
//------------------------------------------------------------------------------
const std::string ausf::get_pid_directory() const {
  return m_pid_directory.get_value();
}
//------------------------------------------------------------------------------
const std::string ausf::get_ausf_name() const {
  return m_ausf_name.get_value();
}

//------------------------------------------------------------------------------
ausf_config_yaml::ausf_config_yaml(
    const std::string& config_path, bool log_stdout, bool log_rot_file)
    : oai::config::config(
          config_path, oai::config::AUSF_CONFIG_NAME, log_stdout,
          log_rot_file) {
  m_used_sbi_values = {
      oai::config::AUSF_CONFIG_NAME, oai::config::UDM_CONFIG_NAME,
      oai::config::NRF_CONFIG_NAME};
  m_used_config_values = {
      oai::config::LOG_LEVEL_CONFIG_NAME, oai::config::REGISTER_NF_CONFIG_NAME,
      NF_CONFIG_HTTP_NAME, oai::config::NF_LIST_CONFIG_NAME,
      oai::config::AUSF_CONFIG_NAME};

  // TODO with NF_Type and switch
  // TODO: Still we need to add default NFs even we don't use this in all_in_one
  // use case
  auto m_ausf = std::make_shared<ausf>(
      "AUSF", "oai-ausf", sbi_interface("SBI", "oai-ausf1", 80, "v1", "eth0"));
  add_nf("ausf", m_ausf);

  auto m_udm = std::make_shared<nf>(
      "UDM", "oai-udm", sbi_interface("SBI", "oai-udm", 80, "v1", "eth0"));
  add_nf("udm", m_udm);

  auto m_nrf = std::make_shared<nf>(
      "NRF", "oai-nrf", sbi_interface("SBI", "oai-nrf", 80, "v1", "eth0"));
  add_nf("nrf", m_nrf);

  update_used_nfs();
}

//------------------------------------------------------------------------------
ausf_config_yaml::~ausf_config_yaml() {}

void ausf_config_yaml::pre_process() {
  // Process configuration information to display only the appropriate
  // information
  // TODO
}

//------------------------------------------------------------------------------
void ausf_config_yaml::to_ausf_config(oai::config::ausf_config& cfg) {
  std::shared_ptr<ausf> ausf_local =
      std::static_pointer_cast<ausf>(get_local());
  cfg.instance             = ausf_local->get_instance_id();
  cfg.pid_dir              = ausf_local->get_pid_directory();
  cfg.ausf_name            = ausf_local->get_ausf_name();
  cfg.log_level            = spdlog::level::from_str(log_level());
  cfg.register_nrf         = register_nrf();
  cfg.http_request_timeout = get_http_request_timeout();

  cfg.http_version    = get_http_version();
  cfg.sbi.api_version = local().get_sbi().get_api_version();
  cfg.sbi.port        = local().get_sbi().get_port();
  cfg.sbi.addr4       = local().get_sbi().get_addr4();
  cfg.sbi.if_name     = local().get_sbi().get_if_name();

  if (get_nf(oai::config::NRF_CONFIG_NAME)) {
    cfg.nrf_addr.api_version = get_nf("nrf")->get_sbi().get_api_version();
    cfg.nrf_addr.uri_root    = get_nf(oai::config::NRF_CONFIG_NAME)->get_url();
  }

  if (get_nf(oai::config::UDM_CONFIG_NAME)) {
    cfg.udm_addr.api_version = get_nf("udm")->get_sbi().get_api_version();
    cfg.udm_addr.uri_root    = get_nf(oai::config::UDM_CONFIG_NAME)->get_url();
  }
}
}  // namespace oai::config
