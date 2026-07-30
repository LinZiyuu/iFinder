/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include <string>
#include <vector>
#include <optional>
#include "api_response.h"
#include "SlicePolicyDecision.h"
#include "handler_base.hpp"

namespace oai::pcf::provisioning::api {

class slice_policy_decisions_handler : public handler_base {
 public:
  /**
   * delete policy decision for slice
   * @param sst
   * @param sd
   * @return api_response
   */
  oai::pcf::api::api_response slice_policy_decision_delete(
      const std::optional<int32_t>& sst, const std::optional<std::string>& sd);

  /**
   * get policy decision for slice
   * @param sst
   * @param sd
   * @return api_response
   */
  oai::pcf::api::api_response slice_policy_decision_get(
      const std::optional<int32_t>& sst, const std::optional<std::string>& sd);

  /**
   * create new slice policy decision
   * @param slicePolicyDecision
   * @return api_response
   */
  oai::pcf::api::api_response slice_policy_decision_post(
      const oai::pcf::provisioning::model::SlicePolicyDecision&
          slicePolicyDecision);

  /**
   * update policy decision for slice
   * @param sst
   * @param sd
   * @param slicePolicyDecision
   * @return api_response
   */
  oai::pcf::api::api_response slice_policy_decision_put(
      const std::optional<int32_t>& sst, const std::optional<std::string>& sd,
      const oai::pcf::provisioning::model::SlicePolicyDecision&
          slicePolicyDecision);

  /**
   * get all slice policy decisions
   * @return api_response
   */
  oai::pcf::api::api_response slice_policy_decisions_get();
};
}  // namespace oai::pcf::provisioning::api
