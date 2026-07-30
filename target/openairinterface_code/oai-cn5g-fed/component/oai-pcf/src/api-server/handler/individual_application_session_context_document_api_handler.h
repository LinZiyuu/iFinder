
/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include "AppSessionContextUpdateDataPatch.h"
#include "EventsSubscReqData.h"
#include "api_response.h"
#include "pcf_policy_authorization.hpp"

namespace oai::pcf::api {

class individual_application_session_context_document_api_handler {
 public:
  explicit individual_application_session_context_document_api_handler(
      const std::shared_ptr<oai::pcf::app::pcf_policy_authorization>&
          pcf_policy_authorization) {
    m_pa_service = pcf_policy_authorization;
  }
  /**
   * Delete Individual Application Session Context based on ID
   * @param app_session_id
   * @param events_subsc_req_data
   * @return api_response
   */
  api_response delete_app_session(
      const std::string& app_session_id,
      const oai::model::pcf::EventsSubscReqData& events_subsc_req_data);

  /**
   * Delete Individual Application Session Context based on ID
   * @param app_session_id
   * @param events_subsc_req_data
   * @return api_response
   */
  api_response get_app_session(const std::string& app_session_id);

  /**
   * Delete Individual Application Session Context based on ID
   * @param app_session_id
   * @param app_session_context_update_data_patch
   * @return api_response
   */
  api_response mod_app_session(
      const std::string& app_session_id,
      const oai::model::pcf::AppSessionContextUpdateDataPatch&
          app_session_context_update_data_patch);

 private:
  std::shared_ptr<oai::pcf::app::pcf_policy_authorization> m_pa_service;
};

}  // namespace oai::pcf::api