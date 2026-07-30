/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include <string>
#include <vector>
#include "api_response.h"
#include "DnnPolicyDecision.h"
#include "handler_base.hpp"

namespace oai::pcf::provisioning::api {

class dnn_policy_decisions_handler : public handler_base {
 public:
  /**
   * delete dnn policy decision for dnn
   * @param dnn
   * @return api_response
   */
  oai::pcf::api::api_response dnn_policy_decision_dnn_delete(
      const std::string& dnn);

  /**
   * get policy decision for dnn
   * @param dnn
   * @return api_response
   */
  oai::pcf::api::api_response dnn_policy_decision_dnn_get(
      const std::string& dnn);

  /**
   * update policy decision for dnn
   * @param dnn
   * @param dnnPolicyDecision
   * @return api_response
   */
  oai::pcf::api::api_response dnn_policy_decision_dnn_put(
      const std::string& dnn,
      const oai::pcf::provisioning::model::DnnPolicyDecision&
          dnnPolicyDecision);

  /**
   * create new dnn policy decision
   * @param dnnPolicyDecision
   * @return api_response
   */
  oai::pcf::api::api_response dnn_policy_decision_post(
      const oai::pcf::provisioning::model::DnnPolicyDecision&
          dnnPolicyDecision);

  /**
   * get all policy decisions
   * @return api_response
   */
  oai::pcf::api::api_response dnn_policy_decisions_get();
};
}  // namespace oai::pcf::provisioning::api
