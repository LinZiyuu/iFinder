/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_POLICY_PROVISIONING_FILE_SEEN
#define FILE_POLICY_PROVISIONING_FILE_SEEN

#include <yaml-cpp/yaml.h>
#include "nlohmann/json.hpp"
#include <vector>
#include "SmPolicyDecision.h"
#include "PccRule.h"
#include "TrafficControlData.h"
#include "policy_storage_yaml.hpp"

namespace oai::pcf::app::sm_policy {

class policy_provisioning_file {
 public:
  bool read_all_policy_files();
  explicit policy_provisioning_file(
      const std::shared_ptr<oai::pcf::app::sm_policy::policy_storage_yaml>&
          policy_storage) {
    m_policy_storage = policy_storage;
  }

 private:
  static bool read_all_files_in_dir(
      const std::string& dir_path, std::vector<YAML::Node>& yaml_output);

  static oai::model::pcf::SmPolicyDecision decision_from_rules(
      const YAML::Node& node,
      const std::map<std::string, oai::model::pcf::PccRule>& pcc_rules,
      const std::map<std::string, oai::model::pcf::TrafficControlData>&
          traffic_control,
      const std::map<std::string, oai::model::pcf::QosData>& qos_data);

  template<class T>
  static std::map<std::string, T> convert_yaml_to_model(
      const std::vector<YAML::Node>& nodes);

  template<class T>
  static void remove_ids_not_in_map(
      const std::map<std::string, T>& map, std::vector<std::string>& ids,
      const std::string& error_msg_type, const std::string& pcc_id);

  std::shared_ptr<oai::pcf::app::sm_policy::policy_storage_yaml>
      m_policy_storage;
};
}  // namespace oai::pcf::app::sm_policy
#endif
