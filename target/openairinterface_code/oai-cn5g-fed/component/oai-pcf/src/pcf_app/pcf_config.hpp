/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include "config.hpp"
#include "pcf_config_types.hpp"

namespace oai::config::pcf {

const std::string DEFAULT_PCC_RULES_PATH = "/openair-pcf/policies/pcc_rules";
const std::string DEFAULT_TRAFFIC_RULES_PATH =
    "/openair-pcf/policies/traffic_rules";
const std::string DEFAULT_POLICY_DECISIONS_PATH =
    "/openair-pcf/policies/policy_decisions";
const std::string DEFAULT_QOS_DATA_PATH = "/openair-pcf/policies/qos_data";

class pcf_config : public oai::config::config {
 public:
  explicit pcf_config(
      const std::string& config_path, bool log_stdout, bool log_rot_file);

  const policy_config& get_pcf_policy() const;
  bool use_db_policy_storage() const;
};
}  // namespace oai::config::pcf
