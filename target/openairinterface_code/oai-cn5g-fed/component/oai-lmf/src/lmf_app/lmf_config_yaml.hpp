/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include "config.hpp"
#include "lmf_config.hpp"

constexpr auto LMF_CONFIG_INSTANCE_ID         = "instance_id";
constexpr auto LMF_CONFIG_INSTANCE_ID_LABEL   = "Instance ID";
constexpr auto LMF_CONFIG_PID_DIRECTORY       = "pid_directory";
constexpr auto LMF_CONFIG_PID_DIRECTORY_LABEL = "PID Directory";
constexpr auto LMF_CONFIG_LMF_NAME            = "lmf_name";
constexpr auto LMF_CONFIG_LMF_NAME_LABEL      = "LMF Name";

constexpr auto LMF_CONFIG_HTTP_THREADS_COUNT        = "http_threads_count";
constexpr auto LMF_CONFIG_HTTP_THREADS_COUNT_LABEL  = "HTTP Threads Count";
constexpr auto LMF_CONFIG_GNB_ID_BITS_COUNT         = "gnb_id_bits_count";
constexpr auto LMF_CONFIG_GNB_ID_BITS_COUNT_LABEL   = "gNB ID Bits Count";
constexpr auto LMF_CONFIG_NUM_GNB                   = "num_gnb";
constexpr auto LMF_CONFIG_NUM_GNB_LABEL             = "Number of gNBs";
constexpr auto LMF_CONFIG_TRP_INFO_WAIT_MS          = "trp_info_wait_ms";
constexpr auto LMF_CONFIG_TRP_INFO_WAIT_MS_LABEL    = "TRP Info Wait (ms)";
constexpr auto LMF_CONFIG_POSITIONING_WAIT_MS       = "positioning_wait_ms";
constexpr auto LMF_CONFIG_POSITIONING_WAIT_MS_LABEL = "Positioning Wait (ms)";
constexpr auto LMF_CONFIG_MEASUREMENT_WAIT_MS       = "measurement_wait_ms";
constexpr auto LMF_CONFIG_MEASUREMENT_WAIT_MS_LABEL = "Positioning Wait (ms)";
constexpr auto LMF_CONFIG_SUPPORT_FEATURES          = "support_features";
constexpr auto LMF_CONFIG_SUPPORT_FEATURES_LABEL    = "Support Features";
constexpr auto LMF_CONFIG_SUPPORT_FEATURES_REQUEST_TRP_INFO =
    "Request_trp_info";
constexpr auto LMF_CONFIG_SUPPORT_FEATURES_REQUEST_TRP_INFO_LABEL =
    "Request TRP Info";
constexpr auto LMF_CONFIG_SUPPORT_FEATURES_DETERMINE_NUM_GNB_INFO =
    "determine_num_gnb";
constexpr auto LMF_CONFIG_SUPPORT_FEATURES_DETERMINE_NUM_GNB_INFO_LABEL =
    "Determine Num gNB";

constexpr auto LMF_CONFIG_INSTANCE_ID_DEFAULT_VALUE       = 1;
constexpr auto LMF_CONFIG_PID_DIRECTORY_DEFAULT_VALUE     = "/var/run";
constexpr auto LMF_CONFIG_LMF_NAME_DEFAULT_VALUE          = "oai-lmf";
constexpr uint8_t LMF_CONFIG_HTTP_THREADS_COUNT_MIN_VALUE = 1;
constexpr uint8_t LMF_CONFIG_HTTP_THREADS_COUNT_MAX_VALUE = 10;  // To be
                                                                 // updated
constexpr uint8_t LMF_CONFIG_HTTP_THREADS_COUNT_DEFAULT_VALUE = 8;
constexpr uint8_t LMF_CONFIG_GNB_ID_BITS_COUNT_MIN_VALUE = 1;   // To be updated
constexpr uint8_t LMF_CONFIG_GNB_ID_BITS_COUNT_MAX_VALUE = 30;  // To be updated
constexpr uint8_t LMF_CONFIG_GNB_ID_BITS_COUNT_DEFAULT_VALUE =
    28;                                                         // To be updated
constexpr uint8_t LMF_CONFIG_NUM_GNB_MIN_VALUE           = 1;   // To be updated
constexpr uint8_t LMF_CONFIG_NUM_GNB_MAX_VALUE           = 10;  // To be updated
constexpr uint8_t LMF_CONFIG_NUM_GNB_DEFAULT_VALUE       = 1;
constexpr uint32_t LMF_CONFIG_TRP_INFO_WAIT_MS_MIN_VALUE = 1;  // To be updated
constexpr uint32_t LMF_CONFIG_TRP_INFO_WAIT_MS_MAX_VALUE =
    100000;  // To be updated
constexpr uint32_t LMF_CONFIG_TRP_INFO_WAIT_MS_DEFAULT_VALUE = 10000;
constexpr uint32_t LMF_CONFIG_POSITIONING_WAIT_MS_MIN_VALUE  = 1;  // To be
                                                                   // updated
constexpr uint32_t LMF_CONFIG_POSITIONING_WAIT_MS_MAX_VALUE =
    100000;  // To be updated
constexpr uint32_t LMF_CONFIG_POSITIONING_WAIT_MS_DEFAULT_VALUE = 10000;
constexpr uint32_t LMF_CONFIG_MEASUREMENT_WAIT_MS_MIN_VALUE     = 1;  // To be
                                                                      // updated
constexpr uint32_t LMF_CONFIG_MEASUREMENT_WAIT_MS_MAX_VALUE =
    100000;  // To be updated
constexpr uint32_t LMF_CONFIG_MEASUREMENT_WAIT_MS_DEFAULT_VALUE = 10000;

namespace oai::config {

class lmf_support_features : public config_type {
 private:
  option_config_value m_request_trp_info{};
  option_config_value m_determine_num_gnb{};

 public:
  explicit lmf_support_features();

  void from_yaml(const YAML::Node& node) override;

  [[nodiscard]] std::string to_string(const std::string& indent) const override;
  [[nodiscard]] bool get_option_request_trp_info() const;
  [[nodiscard]] bool get_option_determine_num_gnb() const;
};

class lmf : public nf {
 private:
  int_config_value m_instance_id;
  string_config_value m_pid_directory;
  string_config_value m_lmf_name;

  int_config_value m_http_threads_count;
  int_config_value m_gnb_id_bits_count;
  int_config_value m_num_gnb;
  int_config_value m_trp_info_wait_ms;
  int_config_value m_positioning_wait_ms;
  int_config_value m_measurement_wait_ms;
  lmf_support_features m_lmf_support_features;

 public:
  explicit lmf(
      const std::string& name, const std::string& host,
      const sbi_interface& sbi);

  void from_yaml(const YAML::Node& node) override;

  [[nodiscard]] std::string to_string(const std::string& indent) const override;
  void validate() override;

  [[nodiscard]] const uint32_t get_instance_id() const;
  [[nodiscard]] const std::string get_pid_directory() const;
  [[nodiscard]] const std::string get_lmf_name() const;
  [[nodiscard]] const uint8_t get_http_threads_count() const;
  [[nodiscard]] const uint8_t get_gnb_id_bits_count() const;
  [[nodiscard]] const uint8_t get_num_gnb() const;
  [[nodiscard]] const uint32_t get_trp_info_wait_ms() const;
  [[nodiscard]] const uint32_t get_positioning_wait_ms() const;
  [[nodiscard]] const uint32_t get_measurement_wait_ms() const;
  lmf_support_features get_support_features() const;
};

class lmf_config_yaml : public config {
 public:
  explicit lmf_config_yaml(
      const std::string& config_path, bool log_stdout, bool log_rot_file);
  virtual ~lmf_config_yaml();

  void to_lmf_config(oai::lmf::config::lmf_config& cfg);
  void pre_process();
};
}  // namespace oai::config
