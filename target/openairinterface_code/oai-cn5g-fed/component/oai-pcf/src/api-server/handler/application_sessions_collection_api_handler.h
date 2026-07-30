/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include "AppSessionContext.h"
#include "Ambr.h"
#include "api_response.h"
#include "pcf_policy_authorization.hpp"

namespace oai::pcf::api {

class application_sessions_collection_api_handler {
 public:
  explicit application_sessions_collection_api_handler(
      const std::shared_ptr<oai::pcf::app::pcf_policy_authorization>&
          pcf_policy_authorization,
      const std::string& address) {
    m_pa_service = pcf_policy_authorization;
    m_address    = address;
  }
  /**
   * Creates a new Individual Application Session Context resource
   * @param app_session_context
   * @return api_response
   */
  api_response post_app_sessions(
      const oai::model::pcf::AppSessionContext& app_session_context);

 private:
  std::shared_ptr<oai::pcf::app::pcf_policy_authorization> m_pa_service;
  std::string m_address;
};

}  // namespace oai::pcf::api