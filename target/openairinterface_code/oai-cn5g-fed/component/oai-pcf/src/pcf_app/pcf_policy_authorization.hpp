/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_PCF_POLICY_AUTHORIZATION_SEEN
#define FILE_PCF_POLICY_AUTHORIZATION_SEEN

#include <string>
#include <unordered_map>
#include <shared_mutex>
#include <memory>
#include <optional>

#include "SmPolicyContextData.h"
#include "SmPolicyDecision.h"
#include "TrafficControlData.h"
#include "AppSessionContext.h"
#include "AppSessionContextUpdateDataPatch.h"
#include "AppSessionContextReqData.h"
#include "policy_auth/pcf_policy_authorization_status_code.hpp"
#include "policy_auth/app_session.hpp"
#include "uint_generator.hpp"
#include "pcf_event.hpp"

namespace oai::pcf::app {

/**
 * @brief Service class to handle Session Management Policies
 *
 */
class pcf_policy_authorization {
 public:
  explicit pcf_policy_authorization(pcf_event& ev);
  pcf_policy_authorization(pcf_policy_authorization const&) = delete;
  void operator=(pcf_policy_authorization const&) = delete;

  virtual ~pcf_policy_authorization();

  /**
   * @brief Handler for receiving service policy requests, as defined in
   * 3GPP TS 29.514 Chapter 4.2.2
   * It creates an application session context in the PCF. The result
   * returns an update context created.
   *
   * @param context input: context from the request
   * provisioning
   * @return policy_auth::status_code
   */
  policy_auth::status_code post_app_sessions_handler(
      const oai::model::pcf::AppSessionContext& context,
      std::string& app_session_id, std::string& problem_details);

  /**
   * @brief Handler for receiving service policy requests to update application
   * session context, as defined in 3GPP TS 29.514 Chapter 4.2.3
   *
   * @param app_session_id input: context from the request
   * @param app_session_context_update_data_patch input: context from the
   * request
   * @param context output: the applications session context that has been
   * updated provisioning
   * @return policy_auth::status_code
   */
  policy_auth::status_code mod_app_session_handler(
      const std::string& app_session_id,
      const oai::model::pcf::AppSessionContextUpdateDataPatch&
          app_session_context_update_data_patch,
      const oai::model::pcf::AppSessionContext& context,
      std::string& problem_details);

 private:
  oai::utils::uint_generator<uint32_t> m_app_sessions_id_generator;

  std::unordered_map<std::string, oai::pcf::app::policy_auth::app_session>
      m_app_sessions;

  mutable std::shared_mutex m_app_sessions_mutex;

  // for Event Handling
  pcf_event& m_event_sub;
};

}  // namespace oai::pcf::app
#endif /* FILE_PCF_POLICY_AUTHORIZATION_SEEN */
