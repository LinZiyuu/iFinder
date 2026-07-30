
/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include "3gpp_29.500.h"
#include "api_response.h"
#include "SmPolicyContextData.h"
#include "pcf_sm_policy_control.hpp"

namespace oai::pcf::api {

class sm_policies_collection_api_handler {
 public:
  sm_policies_collection_api_handler(
      const std::shared_ptr<oai::pcf::app::pcf_smpc>& pcf_smpc,
      const std::string& address) {
    m_address      = address;
    m_smpc_service = pcf_smpc;
  }

  /**
   * Create SM Policy
   * @param sm_policy_context_data SM context data
   * @return api_response with SmPolicyDecision
   */
  api_response create_sm_policy(
      const oai::model::pcf::SmPolicyContextData& sm_policy_context_data);

 private:
  std::string m_address;
  std::shared_ptr<oai::pcf::app::pcf_smpc> m_smpc_service;
};

}  // namespace oai::pcf::api