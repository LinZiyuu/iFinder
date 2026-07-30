/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_APP_SESSION_SEEN
#define FILE_APP_SESSION_SEEN

#include "AppSessionContext.h"
#include "AppSessionContextReqData.h"

namespace oai::pcf::app::policy_auth {

class app_session {
 public:
  explicit app_session(
      const oai::model::pcf::AppSessionContextReqData& context,
      const oai::model::pcf::SmPolicyDecision& decision, const std::string& id)
      : m_decision(decision) {
    m_context = context;
    // TODO [PAS] add association id to be used during update
    m_id = id;
  }

  virtual ~app_session() = default;

  [[nodiscard]] virtual const oai::model::pcf::AppSessionContextReqData&
  get_app_session_context() const;

  [[nodiscard]] virtual void set_app_session_context(
      oai::model::pcf::AppSessionContextReqData& context);

  [[nodiscard]] virtual std::string get_id() const;

 private:
  // TODO: create a struct only for attributes that need to be stored?
  oai::model::pcf::AppSessionContextReqData m_context;
  // TODO: create a struct only for attributes that need to be stored?
  oai::model::pcf::SmPolicyDecision m_decision;
  // attributes that need to be stored
  // reference session
  // reference pcc rules
  std::string m_id;
};

/**
 * Handlers for processing different App Session operation procedures
 *
 * 3GPP TS 29.514 4.2.x
 */

/**
 * Extracts the N6-LAN Traffic Steering Requirements from the given
 * AfSfcRequirement object. 3GPP TS 29.514 4.2.2.8.
 *
 * @param af_sfc           The AfSfcRequirement object containing the SFC
 * requirements.
 * @param traffic_control_data The TrafficControlData object to store the
 * extracted requirements.
 * @param problem_details  A reference string to hold any error details if
 * extraction fails.
 *
 * @return status_code::OK on success or a failure code if an issue occurs
 * during extraction.
 */
oai::pcf::app::policy_auth::handler_result handle_service_function_chaining(
    const oai::model::pcf::AfSfcRequirement& af_sfc,
    oai::model::pcf::SmPolicyDecision& decision);

oai::pcf::app::policy_auth::handler_result
handle_service_function_chaining_update(
    const oai::model::pcf::AfSfcRequirement& af_sfc,
    oai::model::pcf::SmPolicyDecision& decision,
    oai::model::pcf::AppSessionContextReqData& context);

//   oai::pcf::app::policy_auth::status_code handle_traffic_routing(
//       oai::model::pcf::SmPolicyContextData& orig_context,
//       const oai::model::pcf::SmPolicyUpdateContextData& update,
//       std::string& problem_details);

oai::pcf::app::policy_auth::handler_result authorize_service_info(
    const oai::model::pcf::AppSessionContextReqData& reqData);

oai::pcf::app::policy_auth::handler_result validate_and_merge_decision(
    const oai::model::pcf::SmPolicyDecision& request_decision,
    oai::model::pcf::SmPolicyDecision& current_decision, bool update = false);

}  // namespace oai::pcf::app::policy_auth

#endif  // FILE_APP_SESSION_SEEN
