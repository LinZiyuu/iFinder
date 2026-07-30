/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include <nlohmann/json.hpp>

#include "ausf_config.hpp"
#include "sbi_helper.hpp"

using namespace oai::config;
using namespace oai::common::sbi;

extern ausf_config ausf_cfg;

namespace oai::ausf::api {

class ausf_sbi_helper : public sbi_helper {
 public:
  static inline const std::string UEAuthenticationServiceBase =
      sbi_helper::AusfAuthBase +
      ausf_cfg.sbi.api_version.value_or(kDefaultSbiApiVersion);

  static void set_problem_details(
      nlohmann::json& json_data, const std::string& detail);
};

}  // namespace oai::ausf::api
