/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include "EventsSubscReqData.h"
#include "api_response.h"
#include "pcf_policy_authorization.hpp"

namespace oai::pcf::api {

class events_subscription_document_api_handler {
 public:
  explicit events_subscription_document_api_handler(
      const std::shared_ptr<oai::pcf::app::pcf_policy_authorization>&
          pcf_policy_authorization) {
    m_pa_service = pcf_policy_authorization;
  }
  /**
   * Delete Events Subscription based on ID
   * @param app_session_id
   * @return api_response
   */
  api_response delete_events_subsc(const std::string& app_session_id);

  /**
   * Creates or modifies an Events Subscription subresource
   * @param app_session_id
   * @param events_subsc_req_data
   * @return api_response
   */
  api_response update_events_subsc(
      const std::string& app_session_id,
      const oai::model::pcf::EventsSubscReqData& events_subsc_req_data);

 private:
  std::shared_ptr<oai::pcf::app::pcf_policy_authorization> m_pa_service;
};

}  // namespace oai::pcf::api