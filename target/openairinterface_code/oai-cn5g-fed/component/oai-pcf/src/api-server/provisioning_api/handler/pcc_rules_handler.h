/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include <string>
#include <vector>
#include "api_response.h"
#include "PccRule.h"
#include "handler_base.hpp"

namespace oai::pcf::provisioning::api {

class pcc_rules_handler : public handler_base {
 public:
  /**
   *
   * @param pccRuleId
   * @return
   */
  oai::pcf::api::api_response pcc_rule_pcc_rule_id_delete(
      const std::string& pccRuleId);

  /**
   *
   * @param pccRuleId
   * @return
   */
  oai::pcf::api::api_response pcc_rule_pcc_rule_id_get(
      const std::string& pccRuleId);
  /**
   *
   * @param pccRuleId
   * @param pccRule
   * @return
   */
  oai::pcf::api::api_response pcc_rule_pcc_rule_id_put(
      const std::string& pccRuleId, const oai::model::pcf::PccRule& pccRule);

  /**
   *
   * @param pccRule
   * @return
   */
  oai::pcf::api::api_response pcc_rule_post(
      const oai::model::pcf::PccRule& pccRule);
  /**
   *
   * @return
   */
  oai::pcf::api::api_response pcc_rules_get();
};
}  // namespace oai::pcf::provisioning::api
