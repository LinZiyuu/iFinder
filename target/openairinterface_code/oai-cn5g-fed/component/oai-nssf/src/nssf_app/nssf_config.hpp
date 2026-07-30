/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include <yaml-cpp/yaml.h>

#include "logger.hpp"
#include "NsiInformation.h"
#include "SupportedNssaiAvailabilityData.h"
#include "Tai.h"
#include "config.hpp"

namespace oai::config::nssf {

typedef struct nsi_info_s {
  oai::model::common::Snssai snssai;
  oai::nssf_server::model::NsiInformation nsi_info;
} nsi_info_t;

typedef struct nssf_nsi_info_cfg_s {
  std::vector<nsi_info_t> nsi_info_list;
} nssf_nsi_info_t;

typedef struct ta_info_s {
  std::vector<oai::model::common::Snssai> supoorted_snssai;
  oai::model::common::Tai tai;
} ta_info_t;

typedef struct nssf_ta_info_cfg_s {
  std::vector<ta_info_t> ta_info_list;
} nssf_ta_info_t;

typedef struct amf_info_s {
  std::string target_amf_set;
  std::string nrf_amf_set;
  std::string nrf_amf_set_mgt;
  std::vector<std::pair<
      std::string,
      std::vector<oai::nssf_server::model::SupportedNssaiAvailabilityData>>>
      amf_List;
} amf_info_t;

typedef struct nssf_amf_info_cfg_s {
  std::vector<amf_info_t> amf_info_list;
} nssf_amf_info_t;

class nssf_config : public oai::config::config {
 private:
  static bool parse_amf_list(const YAML::Node& conf, amf_info_t& amf_info);

  static bool parse_nssai(
      const YAML::Node& conf,
      oai::nssf_server::model::SupportedNssaiAvailabilityData& nssai_data);

  static bool parse_nsi_info(const YAML::Node& conf, nssf_nsi_info_t& cfg);

  static bool parse_ta_info(const YAML::Node& conf, nssf_ta_info_t& cfg);

  static bool parse_amf_info(const YAML::Node& conf, nssf_amf_info_t& cfg);

 public:
  // Stefan: We should get rid of this instance
  unsigned int instance = 0;
  static nssf_nsi_info_t nssf_nsi_info;
  static nssf_ta_info_t nssf_ta_info;
  static nssf_amf_info_t nssf_amf_info;

  explicit nssf_config(
      const std::string& config_path, bool log_stdout, bool log_rot_file);

  bool parse_config();
  static bool get_slice_config(nlohmann::json& slice_config);
  static bool get_api_list(nlohmann::json& api_list);

  bool init() override;
};
}  // namespace oai::config::nssf
