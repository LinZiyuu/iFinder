/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include <string>
#include <map>
// TODO I think we should get rid of boost and use c++17 std::filesystem
#include "boost/filesystem.hpp"
#include "nlohmann/json.hpp"

#include "policy_provisioning_file.hpp"
#include "pcf_config.hpp"
#include "logger.hpp"
#include "Snssai.h"
#include "conversions.hpp"

using namespace oai::pcf::app;
using namespace oai::config::pcf;
using namespace oai::pcf::app::sm_policy;
using namespace oai::model::pcf;
using namespace boost::filesystem;
using namespace oai::model::common;

extern std::unique_ptr<pcf_config> pcf_cfg;

bool policy_provisioning_file::read_all_policy_files() {
  // first start at the traffic descriptions as they are referenced
  std::vector<YAML::Node> traffic_controls;
  std::vector<YAML::Node> pcc_rules;
  std::vector<YAML::Node> policy_decisions;
  std::vector<YAML::Node> qos_data;

  if (!read_all_files_in_dir(
          pcf_cfg->get_pcf_policy().get_traffic_rules_path(),
          traffic_controls)) {
    Logger::pcf_app().warn("Could not load Traffic Control Description files");
  }
  if (!read_all_files_in_dir(
          pcf_cfg->get_pcf_policy().get_pcc_rules_path(), pcc_rules)) {
    Logger::pcf_app().error("Could not load mandatory PCC rules");
    return false;
  }
  if (!read_all_files_in_dir(
          pcf_cfg->get_pcf_policy().get_policy_decisions_path(),
          policy_decisions)) {
    Logger::pcf_app().error(
        "Could not load mandatory policy decisions configuration");
    return false;
  }
  if (!read_all_files_in_dir(
          pcf_cfg->get_pcf_policy().get_qos_data_path(), qos_data)) {
    Logger::pcf_app().warn("Could not load QoS Data files");
  }

  auto traffic_control_objects =
      convert_yaml_to_model<TrafficControlData>(traffic_controls);
  auto pcc_rule_objects = convert_yaml_to_model<PccRule>(pcc_rules);
  auto qos_data_objects = convert_yaml_to_model<QosData>(qos_data);

  if (traffic_control_objects.empty()) {
    Logger::pcf_app().warn("No traffic control descriptions are loaded");
  }
  if (qos_data_objects.empty()) {
    Logger::pcf_app().warn("No QoS data descriptions are loaded");
  }
  if (pcc_rule_objects.empty()) {
    Logger::pcf_app().warn("No mandatory PCC rules are loaded");
    return false;
  }

  // we need to manually adjust the IDs of the PCC rules and traffic controls
  for (auto& traffic : traffic_control_objects) {
    traffic.second.setTcId(traffic.first);
  }
  for (auto& qos : qos_data_objects) {
    qos.second.setQosId(qos.first);
  }
  for (auto& pcc : pcc_rule_objects) {
    pcc.second.setPccRuleId(pcc.first);

    auto reftc = pcc.second.getRefTcData();
    remove_ids_not_in_map<TrafficControlData>(
        traffic_control_objects, reftc, "Traffic Rules", pcc.first);

    auto refqos = pcc.second.getRefQosData();
    remove_ids_not_in_map<QosData>(
        qos_data_objects, refqos, "QoS Data", pcc.first);

    pcc.second.setRefTcData(reftc);
    pcc.second.setRefQosData(refqos);
  }

  // Now parse the decisions (manually as it is not a model)
  for (auto node : policy_decisions) {
    for (auto it = node.begin(); it != node.end(); ++it) {
      SmPolicyDecision decision = decision_from_rules(
          it->second, pcc_rule_objects, traffic_control_objects,
          qos_data_objects);
      if (!decision.pccRulesIsSet()) {
        Logger::pcf_app().warn(
            "Decision %s could not be parsed. It is ignored",
            it->first.as<std::string>().c_str());
        continue;
      }

      if (it->second["supi_imsi"]) {
        std::string supi = "imsi-" + it->second["supi_imsi"].as<std::string>();
        m_policy_storage->insert_supi_decision(supi, decision);
      } else if (it->second["dnn"]) {
        auto dnn = it->second["dnn"].as<std::string>();
        m_policy_storage->insert_dnn_decision(dnn, decision);
      } else if (it->second["slice"]) {
        Snssai snssai;
        try {
          auto sd = it->second["slice"]["sd"].as<std::string>();
          int sst = it->second["slice"]["sst"].as<int>();
          snssai.setSd(sd);
          snssai.setSst(sst);
          m_policy_storage->insert_slice_decision(snssai, decision);
        } catch (YAML::Exception& ex) {
          Logger::pcf_app().warn(
              "Error while parsing slice decision: %s", ex.msg.c_str());
        }
      } else {
        // when nothing is configured or "default" or whatever, use default
        m_policy_storage->set_default_decision(decision);
      }
      Logger::pcf_app().debug(
          "Decision %s successfully parsed.",
          it->first.as<std::string>().c_str());
    }
  }

  Logger::pcf_app().info("Reading the Policies from file was successful");
  Logger::pcf_app().debug(m_policy_storage->to_string());
  return true;
}

SmPolicyDecision policy_provisioning_file::decision_from_rules(
    const YAML::Node& node, const std::map<std::string, PccRule>& pcc_rules,
    const std::map<std::string, TrafficControlData>& traffic_control,
    const std::map<std::string, QosData>& qos_data) {
  SmPolicyDecision decision = {};

  std::map<std::string, PccRule> used_rules;

  if (node["pcc_rules"]) {
    for (auto it = node["pcc_rules"].begin(); it != node["pcc_rules"].end();
         ++it) {
      try {
        auto key   = it->as<std::string>();
        auto found = pcc_rules.find(key);
        if (found == pcc_rules.end()) {
          Logger::pcf_app().warn(
              "You configured PCC rule %s in policy decision, but it does not "
              "exist. This rule is not considered.",
              key.c_str());
        } else {
          used_rules.insert(std::make_pair(key, found->second));
        }
      } catch (YAML::Exception& ex) {
        Logger::pcf_app().error(
            "Error while parsing decision: %s. Please check your file.",
            ex.msg.c_str());
        return {};
      }
    }
  } else {
    Logger::pcf_app().warn("You did not set mandatory PCC rules for Decision");
    return {};
  }
  std::map<std::string, TrafficControlData> used_traffic_control;
  std::map<std::string, QosData> used_qos_data;

  // now add the TrafficControlDescriptions and QosData
  for (const auto& rule : used_rules) {
    for (const auto& traffic : rule.second.getRefTcData()) {
      auto found = traffic_control.find(traffic);
      if (found != traffic_control.end()) {
        used_traffic_control.insert(std::make_pair(traffic, found->second));
      }
    }
    for (const auto& qos : rule.second.getRefQosData()) {
      auto found = qos_data.find(qos);
      if (found != qos_data.end()) {
        used_qos_data.insert(std::make_pair(qos, found->second));
      }
    }
  }
  if (!used_rules.empty()) {
    decision.setPccRules(used_rules);
    decision.setTraffContDecs(used_traffic_control);
    decision.setQosDecs(used_qos_data);
    return decision;
  }
  return {};
}

template<class T>
std::map<std::string, T> policy_provisioning_file::convert_yaml_to_model(
    const std::vector<YAML::Node>& nodes) {
  std::map<std::string, T> objects_map;
  for (const auto& node : nodes) {
    auto j = oai::utils::conv::yaml_to_json(node);

    for (const auto& elem : j.items()) {
      T obj;
      try {
        from_json(elem.value(), obj);
        std::stringstream stream;
        if (obj.validate(stream)) {
          objects_map.insert(std::make_pair(elem.key(), obj));
          Logger::pcf_app().debug(
              "Rule %s successfully parsed.", elem.key().c_str());
        } else {
          Logger::pcf_app().warn(
              "Error while parsing rule %s: %s", elem.key(),
              stream.str().c_str());
        }
      } catch (std::exception& e) {
        Logger::pcf_app().warn(
            "Error while parsing rule %s: %s", elem.key(), e.what());
      }
    }
  }
  return objects_map;
}

template<class T>
void policy_provisioning_file::remove_ids_not_in_map(
    const std::map<std::string, T>& map, std::vector<std::string>& ids,
    const std::string& error_msg_type, const std::string& pcc_id) {
  auto it = ids.begin();
  while (it != ids.end()) {
    auto traffic_exists = map.find(*it);
    if (traffic_exists == map.end()) {
      Logger::pcf_app().warn(
          "You have referenced %s ID %s in PCC Rule %s, but it "
          "does not exist. It is removed from this PCC rule",
          error_msg_type, *it, pcc_id);
      it = ids.erase(it);
    } else {
      ++it;
    }
  }
}

bool policy_provisioning_file::read_all_files_in_dir(
    const std::string& dir_path, std::vector<YAML::Node>& yaml_output) {
  if (!exists(dir_path)) {
    Logger::pcf_app().warn(
        "The directory %s does not exist!", dir_path.c_str());
    return false;
  }
  directory_iterator end_it;  // past end

  std::vector<std::string> filenames;

  for (directory_iterator it(dir_path); it != end_it; ++it) {
    if (!is_directory(it->status())) {
      filenames.push_back(it->path().native());
    }
  }

  for (const auto& path : filenames) {
    YAML::Node node;
    try {
      node = YAML::LoadFile(path);
      yaml_output.push_back(node);
    } catch (YAML::BadFile& ex) {
      Logger::pcf_app().warn(
          "Something went wrong while reading the YAML file: %s",
          ex.msg.c_str());
    }
  }
  return !yaml_output.empty();
}