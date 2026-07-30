/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "api_defs.h"

#include "pcf_config.hpp"

extern std::unique_ptr<oai::config::pcf::pcf_config> pcf_cfg;

namespace oai::pcf::api {

std::string sm_policies::get_route() {
  return API_BASE + pcf_cfg->local().get_sbi().get_api_version() +
         sm_policies::CREATE_ROUTE;
}

std::string app_sessions::get_route() {
  return API_BASE + pcf_cfg->local().get_sbi().get_api_version() +
         app_sessions::CREATE_ROUTE;
}

std::string policy_decision_provisioning::get_provisioning_base() {
  return API_BASE + pcf_cfg->local().get_sbi().get_api_version();
}

}  // namespace oai::pcf::api
