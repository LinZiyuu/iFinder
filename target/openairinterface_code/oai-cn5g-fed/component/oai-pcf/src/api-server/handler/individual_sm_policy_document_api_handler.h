
/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include "3gpp_29.500.h"
#include "api_response.h"
#include "pcf_sm_policy_control.hpp"
#include "SmPolicyDeleteData.h"
#include "SmPolicyUpdateContextData.h"

namespace oai::pcf::api {

class individual_sm_policy_document_api_handler {
 public:
  explicit individual_sm_policy_document_api_handler(
      const std::shared_ptr<oai::pcf::app::pcf_smpc>& pcf_smpc) {
    m_smpc_service = pcf_smpc;
  }
  /**
   * Delete SM Policy based on ID
   * @param sm_policy_id
   * @param sm_policy_delete_data
   * @return api_response
   */
  api_response delete_sm_policy(
      const std::string& sm_policy_id,
      const oai::model::pcf::SmPolicyDeleteData& sm_policy_delete_data);

  /**
   * Get SM Policy by ID
   * @param sm_policy_id
   * @return api_response
   */
  api_response get_sm_policy(const std::string& sm_policy_id);

  /**
   * Update SM Policy by ID and mandatory update context data
   * @param sm_policy_id
   * @param smPolicyUpdateContextData
   * @return
   */
  api_response update_sm_policy(
      const std::string& sm_policy_id,
      const oai::model::pcf::SmPolicyUpdateContextData&
          smPolicyUpdateContextData);

 private:
  std::shared_ptr<oai::pcf::app::pcf_smpc> m_smpc_service;
};

}  // namespace oai::pcf::api