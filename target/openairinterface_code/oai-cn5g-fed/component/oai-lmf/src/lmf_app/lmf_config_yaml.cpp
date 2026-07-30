/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "lmf_config_yaml.hpp"

#include <boost/algorithm/string.hpp>

#include "conversions.hpp"
#include "logger.hpp"

namespace oai::config {

//------------------------------------------------------------------------------
lmf_support_features::lmf_support_features() {
  m_set = true;
}

//------------------------------------------------------------------------------
void lmf_support_features::from_yaml(const YAML::Node& node) {
  if (node[LMF_CONFIG_SUPPORT_FEATURES_REQUEST_TRP_INFO]) {
    m_request_trp_info.from_yaml(
        node[LMF_CONFIG_SUPPORT_FEATURES_REQUEST_TRP_INFO]);
  }
  if (node[LMF_CONFIG_SUPPORT_FEATURES_DETERMINE_NUM_GNB_INFO]) {
    m_determine_num_gnb.from_yaml(
        node[LMF_CONFIG_SUPPORT_FEATURES_DETERMINE_NUM_GNB_INFO]);
  }
}

//------------------------------------------------------------------------------
std::string lmf_support_features::to_string(const std::string& indent) const {
  std::string out;
  unsigned int inner_width = get_inner_width(indent.length());

  std::string request_trp_info_str = m_request_trp_info.get_value() ?
                                         LMF_CONFIG_OPTION_YES_STR :
                                         LMF_CONFIG_OPTION_NO_STR;
  out.append(indent).append(fmt::format(
      BASE_FORMATTER, INNER_LIST_ELEM,
      LMF_CONFIG_SUPPORT_FEATURES_REQUEST_TRP_INFO_LABEL, inner_width,
      request_trp_info_str));

  std::string determine_num_gnb_str = m_determine_num_gnb.get_value() ?
                                          LMF_CONFIG_OPTION_YES_STR :
                                          LMF_CONFIG_OPTION_NO_STR;
  out.append(indent).append(fmt::format(
      BASE_FORMATTER, INNER_LIST_ELEM,
      LMF_CONFIG_SUPPORT_FEATURES_DETERMINE_NUM_GNB_INFO_LABEL, inner_width,
      determine_num_gnb_str));
  return out;
}

//------------------------------------------------------------------------------
bool lmf_support_features::get_option_request_trp_info() const {
  return m_request_trp_info.get_value();
}

//------------------------------------------------------------------------------
bool lmf_support_features::get_option_determine_num_gnb() const {
  return m_determine_num_gnb.get_value();
}

//------------------------------------------------------------------------------
lmf::lmf(
    const std::string& name, const std::string& host, const sbi_interface& sbi)
    : nf(name, host, sbi) {
  m_instance_id = int_config_value(
      LMF_CONFIG_INSTANCE_ID, LMF_CONFIG_INSTANCE_ID_DEFAULT_VALUE);
  m_pid_directory = string_config_value(
      LMF_CONFIG_PID_DIRECTORY, LMF_CONFIG_PID_DIRECTORY_DEFAULT_VALUE);
  m_lmf_name = string_config_value(
      LMF_CONFIG_LMF_NAME, LMF_CONFIG_LMF_NAME_DEFAULT_VALUE);

  m_http_threads_count = int_config_value(
      LMF_CONFIG_HTTP_THREADS_COUNT,
      LMF_CONFIG_HTTP_THREADS_COUNT_DEFAULT_VALUE);
  m_http_threads_count.set_validation_interval(
      LMF_CONFIG_HTTP_THREADS_COUNT_MIN_VALUE,
      LMF_CONFIG_HTTP_THREADS_COUNT_MAX_VALUE);

  m_gnb_id_bits_count = int_config_value(
      LMF_CONFIG_GNB_ID_BITS_COUNT, LMF_CONFIG_GNB_ID_BITS_COUNT_DEFAULT_VALUE);
  m_gnb_id_bits_count.set_validation_interval(
      LMF_CONFIG_GNB_ID_BITS_COUNT_MIN_VALUE,
      LMF_CONFIG_GNB_ID_BITS_COUNT_MAX_VALUE);

  m_num_gnb =
      int_config_value(LMF_CONFIG_NUM_GNB, LMF_CONFIG_NUM_GNB_DEFAULT_VALUE);
  m_num_gnb.set_validation_interval(
      LMF_CONFIG_NUM_GNB_MIN_VALUE, LMF_CONFIG_NUM_GNB_MAX_VALUE);

  m_trp_info_wait_ms = int_config_value(
      LMF_CONFIG_TRP_INFO_WAIT_MS, LMF_CONFIG_TRP_INFO_WAIT_MS_DEFAULT_VALUE);
  m_trp_info_wait_ms.set_validation_interval(
      LMF_CONFIG_TRP_INFO_WAIT_MS_MIN_VALUE,
      LMF_CONFIG_TRP_INFO_WAIT_MS_MAX_VALUE);

  m_positioning_wait_ms = int_config_value(
      LMF_CONFIG_POSITIONING_WAIT_MS,
      LMF_CONFIG_POSITIONING_WAIT_MS_DEFAULT_VALUE);
  m_positioning_wait_ms.set_validation_interval(
      LMF_CONFIG_POSITIONING_WAIT_MS_MIN_VALUE,
      LMF_CONFIG_POSITIONING_WAIT_MS_MAX_VALUE);

  m_measurement_wait_ms = int_config_value(
      LMF_CONFIG_MEASUREMENT_WAIT_MS,
      LMF_CONFIG_MEASUREMENT_WAIT_MS_DEFAULT_VALUE);
  m_measurement_wait_ms.set_validation_interval(
      LMF_CONFIG_MEASUREMENT_WAIT_MS_MIN_VALUE,
      LMF_CONFIG_MEASUREMENT_WAIT_MS_MAX_VALUE);
}

void lmf::from_yaml(const YAML::Node& node) {
  nf::from_yaml(node);

  // Load LMF specified parameter
  for (const auto& elem : node) {
    auto key = elem.first.as<std::string>();

    if (key == LMF_CONFIG_INSTANCE_ID) {
      m_instance_id.from_yaml(elem.second);
    }

    if (key == LMF_CONFIG_PID_DIRECTORY) {
      m_pid_directory.from_yaml(elem.second);
    }

    if (key == LMF_CONFIG_LMF_NAME) {
      m_lmf_name.from_yaml(elem.second);
    }

    if (key == LMF_CONFIG_HTTP_THREADS_COUNT) {
      m_http_threads_count.from_yaml(elem.second);
    }

    if (key == LMF_CONFIG_GNB_ID_BITS_COUNT) {
      m_gnb_id_bits_count.from_yaml(elem.second);
    }

    if (key == LMF_CONFIG_NUM_GNB) {
      m_num_gnb.from_yaml(elem.second);
    }

    if (key == LMF_CONFIG_TRP_INFO_WAIT_MS) {
      m_trp_info_wait_ms.from_yaml(elem.second);
    }

    if (key == LMF_CONFIG_POSITIONING_WAIT_MS) {
      m_positioning_wait_ms.from_yaml(elem.second);
    }

    if (key == LMF_CONFIG_MEASUREMENT_WAIT_MS) {
      m_measurement_wait_ms.from_yaml(elem.second);
    }

    if (key == LMF_CONFIG_SUPPORT_FEATURES) {
      m_lmf_support_features.from_yaml(elem.second);
    }
  }
}

//------------------------------------------------------------------------------
std::string lmf::to_string(const std::string& indent) const {
  std::string out;
  std::string inner_indent = indent + indent;
  unsigned int inner_width = get_inner_width(inner_indent.length());

  out.append(indent).append(nf::to_string(indent));

  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, OUTER_LIST_ELEM, LMF_CONFIG_INSTANCE_ID_LABEL,
          inner_width, m_instance_id.get_value()));

  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, OUTER_LIST_ELEM, LMF_CONFIG_PID_DIRECTORY_LABEL,
          inner_width, m_pid_directory.get_value()));

  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, OUTER_LIST_ELEM, LMF_CONFIG_LMF_NAME_LABEL,
          inner_width, m_lmf_name.get_value()));

  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, OUTER_LIST_ELEM, LMF_CONFIG_HTTP_THREADS_COUNT_LABEL,
          inner_width, m_http_threads_count.get_value()));

  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, OUTER_LIST_ELEM, LMF_CONFIG_GNB_ID_BITS_COUNT_LABEL,
          inner_width, m_gnb_id_bits_count.get_value()));

  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, OUTER_LIST_ELEM, LMF_CONFIG_NUM_GNB_LABEL,
          inner_width, m_num_gnb.get_value()));

  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, OUTER_LIST_ELEM, LMF_CONFIG_TRP_INFO_WAIT_MS_LABEL,
          inner_width, m_trp_info_wait_ms.get_value()));

  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, OUTER_LIST_ELEM, LMF_CONFIG_POSITIONING_WAIT_MS_LABEL,
          inner_width, m_positioning_wait_ms.get_value()));

  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, OUTER_LIST_ELEM, LMF_CONFIG_MEASUREMENT_WAIT_MS_LABEL,
          inner_width, m_measurement_wait_ms.get_value()));

  out.append(inner_indent)
      .append(fmt::format(
          "{} {}\n", OUTER_LIST_ELEM, LMF_CONFIG_SUPPORT_FEATURES_LABEL));
  out.append(m_lmf_support_features.to_string(inner_indent + indent));

  return out;
}

//------------------------------------------------------------------------------
void lmf::validate() {
  nf::validate();
  m_instance_id.validate();
  m_http_threads_count.validate();
  m_gnb_id_bits_count.validate();
  m_num_gnb.validate();
  m_trp_info_wait_ms.validate();
  m_positioning_wait_ms.validate();
  m_measurement_wait_ms.validate();
}

//------------------------------------------------------------------------------
const uint32_t lmf::get_instance_id() const {
  return m_instance_id.get_value();
}

//------------------------------------------------------------------------------
const std::string lmf::get_pid_directory() const {
  return m_pid_directory.get_value();
}

//------------------------------------------------------------------------------
const std::string lmf::get_lmf_name() const {
  return m_lmf_name.get_value();
}

//------------------------------------------------------------------------------
const uint8_t lmf::get_http_threads_count() const {
  return m_http_threads_count.get_value();
}

//------------------------------------------------------------------------------
const uint8_t lmf::get_gnb_id_bits_count() const {
  return m_gnb_id_bits_count.get_value();
}

//------------------------------------------------------------------------------
const uint8_t lmf::get_num_gnb() const {
  return m_num_gnb.get_value();
}

//------------------------------------------------------------------------------
const uint32_t lmf::get_trp_info_wait_ms() const {
  return m_trp_info_wait_ms.get_value();
}

//------------------------------------------------------------------------------
const uint32_t lmf::get_positioning_wait_ms() const {
  return m_positioning_wait_ms.get_value();
}

//------------------------------------------------------------------------------
const uint32_t lmf::get_measurement_wait_ms() const {
  return m_measurement_wait_ms.get_value();
}

//------------------------------------------------------------------------------
lmf_support_features lmf::get_support_features() const {
  return m_lmf_support_features;
}

//------------------------------------------------------------------------------
lmf_config_yaml::lmf_config_yaml(
    const std::string& config_path, bool log_stdout, bool log_rot_file)
    : oai::config::config(
          config_path, oai::config::LMF_CONFIG_NAME, log_stdout, log_rot_file) {
  m_used_sbi_values = {
      oai::config::LMF_CONFIG_NAME, oai::config::AMF_CONFIG_NAME,
      oai::config::NRF_CONFIG_NAME};
  m_used_config_values = {oai::config::LOG_LEVEL_CONFIG_NAME,
                          oai::config::REGISTER_NF_CONFIG_NAME,
                          oai::config::NF_CONFIG_HTTP_NAME,
                          oai::config::NF_CONFIG_HTTP_REQUEST_TIMEOUT,
                          oai::config::NF_LIST_CONFIG_NAME,
                          oai::config::LMF_CONFIG_NAME};

  // TODO with NF_Type and switch
  auto m_lmf = std::make_shared<lmf>(
      "LMF", "oai-lmf", sbi_interface("SBI", "oai-lmf", 80, "v1", "eth0"));
  add_nf(oai::config::LMF_CONFIG_NAME, m_lmf);

  auto m_amf = std::make_shared<nf>(
      "AMF", "oai-amf", sbi_interface("SBI", "oai-amf", 80, "v1", "eth0"));
  add_nf(oai::config::AMF_CONFIG_NAME, m_amf);

  auto m_nrf = std::make_shared<nf>(
      "NRF", "oai-nrf", sbi_interface("SBI", "oai-nrf", 80, "v1", "eth0"));
  add_nf(oai::config::NRF_CONFIG_NAME, m_nrf);

  update_used_nfs();
}

//------------------------------------------------------------------------------
lmf_config_yaml::~lmf_config_yaml() {}

//------------------------------------------------------------------------------
void lmf_config_yaml::pre_process() {
  // Process configuration information to display only the appropriate
  // information
  // TODO: discover UDR via NRF
  std::shared_ptr<nf> amf = get_nf(oai::config::AMF_CONFIG_NAME);
  amf->set_config();
}

//------------------------------------------------------------------------------
void lmf_config_yaml::to_lmf_config(oai::lmf::config::lmf_config& cfg) {
  std::shared_ptr<lmf> lmf_local = std::static_pointer_cast<lmf>(get_local());
  cfg.instance                   = lmf_local->get_instance_id();
  cfg.pid_dir                    = lmf_local->get_pid_directory();
  cfg.lmf_name                   = lmf_local->get_lmf_name();
  cfg.log_level                  = spdlog::level::from_str(log_level());
  cfg.register_nrf               = register_nrf();
  cfg.http_request_timeout       = get_http_request_timeout();

  if (get_http_version() == 2) cfg.use_http2 = true;

  cfg.sbi.api_version = local().get_sbi().get_api_version();
  cfg.sbi.port        = local().get_sbi().get_port();
  cfg.sbi.addr4       = local().get_sbi().get_addr4();
  cfg.sbi.if_name     = local().get_sbi().get_if_name();

  cfg.http_threads_count = lmf_local->get_http_threads_count();
  cfg.gnb_id_bits_count  = lmf_local->get_gnb_id_bits_count();
  cfg.num_gnb            = lmf_local->get_num_gnb();
  cfg.trp_info_wait_ms =
      std::chrono::milliseconds(lmf_local->get_trp_info_wait_ms());
  cfg.positioning_wait_ms =
      std::chrono::milliseconds(lmf_local->get_positioning_wait_ms());
  cfg.measurement_wait_ms =
      std::chrono::milliseconds(lmf_local->get_measurement_wait_ms());
  cfg.determine_num_gnb =
      lmf_local->get_support_features().get_option_determine_num_gnb();
  cfg.request_trp_info =
      lmf_local->get_support_features().get_option_request_trp_info();

  if (get_nf(oai::config::NRF_CONFIG_NAME)) {
    cfg.nrf_addr.api_version =
        get_nf(oai::config::NRF_CONFIG_NAME)->get_sbi().get_api_version();
    cfg.nrf_addr.uri_root = get_nf(oai::config::NRF_CONFIG_NAME)->get_url();
  }

  if (get_nf(oai::config::AMF_CONFIG_NAME)) {
    cfg.amf_addr.api_version =
        get_nf(oai::config::AMF_CONFIG_NAME)->get_sbi().get_api_version();
    cfg.amf_addr.uri_root = get_nf(oai::config::AMF_CONFIG_NAME)->get_url();
  }
}
}  // namespace oai::config
