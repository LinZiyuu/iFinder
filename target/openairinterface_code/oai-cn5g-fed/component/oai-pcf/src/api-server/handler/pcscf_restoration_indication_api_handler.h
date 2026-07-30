/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include "PcscfRestorationRequestData.h"
#include "api_response.h"
#include "pcf_policy_authorization.hpp"
#include "SmPolicyDeleteData.h"
// #include "SmPolicyUpdateContextData.h"

namespace oai::pcf::api {

class pcscf_restoration_indication_api_handler {
 public:
  explicit pcscf_restoration_indication_api_handler(
      const std::shared_ptr<oai::pcf::app::pcf_policy_authorization>&
          pcf_policy_authorization) {
    m_pa_service = pcf_policy_authorization;
  }
  /**
   * Indicates P-CSCF restoration
   * @param pcscf_restoration_request_data
   * @return api_response
   */
  api_response pcscf_restoration(
      const oai::model::pcf::PcscfRestorationRequestData&
          pcscf_restoration_request_data);

 private:
  std::shared_ptr<oai::pcf::app::pcf_policy_authorization> m_pa_service;
};

}  // namespace oai::pcf::api