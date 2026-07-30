/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include <string>
#include <vector>
#include "api_response.h"
#include "SupiPolicyDecision.h"
#include "handler_base.hpp"

namespace oai::pcf::provisioning::api {

class supi_policy_decisions_handler : public handler_base {
 public:
  /**
   * create new supi policy decision
   * @param supiPolicyDecision
   * @return api_response
   */
  oai::pcf::api::api_response supi_policy_decision_post(
      const oai::pcf::provisioning::model::SupiPolicyDecision&
          supiPolicyDecision);

  /**
   * delete policy decision for supi
   * @param supi
   * @return api_response
   */
  oai::pcf::api::api_response supi_policy_decision_supi_delete(
      const std::string& supi);

  /**
   * get policy decision for supi
   * @param supi
   * @return api_response
   */
  oai::pcf::api::api_response supi_policy_decision_supi_get(
      const std::string& supi);

  /**
   * update policy decision for supi
   * @param supi
   * @param supiPolicyDecision
   * @return api_response
   */
  oai::pcf::api::api_response supi_policy_decision_supi_put(
      const std::string& supi,
      const oai::pcf::provisioning::model::SupiPolicyDecision&
          supiPolicyDecision);

  /**
   * get all supi policy decisions
   * @return api_response
   */
  oai::pcf::api::api_response supi_policy_decisions_get();
};
}  // namespace oai::pcf::provisioning::api
