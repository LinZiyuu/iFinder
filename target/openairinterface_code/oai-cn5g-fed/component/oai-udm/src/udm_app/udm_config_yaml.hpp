/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include "config.hpp"
#include "udm_config.hpp"

constexpr auto UDM_CONFIG_INSTANCE_ID         = "instance_id";
constexpr auto UDM_CONFIG_INSTANCE_ID_LABEL   = "Instance ID";
constexpr auto UDM_CONFIG_PID_DIRECTORY       = "pid_directory";
constexpr auto UDM_CONFIG_PID_DIRECTORY_LABEL = "PID Directory";
constexpr auto UDM_CONFIG_UDM_NAME            = "udm_name";
constexpr auto UDM_CONFIG_UDM_NAME_LABEL      = "UDM Name";

constexpr auto UDM_CONFIG_SUBSCRIBER_PROFILE_LIST       = "subscriber_profiles";
constexpr auto UDM_CONFIG_SUBSCRIBER_PROFILE_LIST_LABEL = "Subscriber Profiles";
constexpr auto UDM_CONFIG_SUBSCRIBER_PROFILE            = "subscriber_profile";
constexpr auto UDM_CONFIG_SUBSCRIBER_PROFILE_LABEL      = "Subscriber Profile";
constexpr auto UDM_CONFIG_PROTECTION_SCHEME             = "protection_scheme";
constexpr auto UDM_CONFIG_PROTECTION_SCHEME_LABEL       = "Protection Scheme";
constexpr auto UDM_CONFIG_HOME_NETWORK_PUBLIC_KEY = "home_network_public_key";
constexpr auto UDM_CONFIG_HOME_NETWORK_PUBLIC_KEY_LABEL =
    "Home Network Public Key";
constexpr auto UDM_CONFIG_HOME_NETWORK_PRIVATE_KEY = "home_network_private_key";
constexpr auto UDM_CONFIG_HOME_NETWORK_PRIVATE_KEY_LABEL =
    "Home Network Private Key";
constexpr auto UDM_CONFIG_HOME_NETWORK_PUBLIC_KEY_ID =
    "home_network_public_key_id";
constexpr auto UDM_CONFIG_HOME_NETWORK_PUBLIC_KEY_ID_LABEL =
    "Home Network Public Key ID";

namespace oai::config {

class subscriber_profile : public config_type {
 private:
  int_config_value m_protection_scheme{};
  string_config_value m_home_network_public_key{};
  string_config_value m_home_network_private_key{};
  string_config_value m_home_network_public_key_id{};

 public:
  explicit subscriber_profile();
  explicit subscriber_profile(
      const uint8_t& protection_scheme,
      const std::string& home_network_public_key,
      const std::string& home_network_private_key,
      const std::string& home_network_public_key_id);

  void from_yaml(const YAML::Node& node) override;

  void validate() override;
  void set_validation_regex(const std::string& regex);

  [[nodiscard]] std::string to_string(const std::string& indent) const override;
  [[nodiscard]] uint8_t get_protection_scheme() const;
  [[nodiscard]] std::string get_home_network_public_key() const;
  [[nodiscard]] std::string get_home_network_private_key() const;
  [[nodiscard]] std::string get_home_network_public_key_id() const;
};

class udm : public nf {
 private:
  int_config_value m_instance_id;
  string_config_value m_pid_directory;
  string_config_value m_udm_name;
  std::vector<subscriber_profile> m_subscriber_profile_list;

 public:
  explicit udm(
      const std::string& name, const std::string& host,
      const sbi_interface& sbi);

  void from_yaml(const YAML::Node& node) override;

  [[nodiscard]] std::string to_string(const std::string& indent) const override;
  [[nodiscard]] const uint32_t get_instance_id() const;
  [[nodiscard]] const std::string get_pid_directory() const;
  [[nodiscard]] const std::string get_udm_name() const;
  [[nodiscard]] const std::vector<subscriber_profile>
  get_subscriber_profile_list() const;
};

class udm_config_yaml : public config {
 public:
  explicit udm_config_yaml(
      const std::string& config_path, bool log_stdout, bool log_rot_file);
  virtual ~udm_config_yaml();

  void to_udm_config(oai::udm::config::udm_config& cfg);
  void pre_process();
};
}  // namespace oai::config
