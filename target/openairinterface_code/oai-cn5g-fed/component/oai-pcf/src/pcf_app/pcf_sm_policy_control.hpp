/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_PCF_SM_POLICY_CONTROL_SEEN
#define FILE_PCF_SM_POLICY_CONTROL_SEEN

#include <string>
#include <unordered_map>
#include <shared_mutex>
#include <memory>
#include <optional>

#include "SmPolicyContextData.h"
#include "SmPolicyDecision.h"
#include "SmPolicyDeleteData.h"
#include "SmPolicyControl.h"
#include "SmPolicyUpdateContextData.h"
#include "sm_policy/pcf_smpc_status_code.hpp"
#include "sm_policy/individual_sm_association.hpp"
#include "uint_generator.hpp"
#include "sm_policy/policy_storage.hpp"
#include "pcf_event.hpp"

namespace oai::pcf::app {

/**
 * @brief Service class to handle Session Management Policies
 *
 */
class pcf_smpc {
 public:
  explicit pcf_smpc(
      const std::shared_ptr<oai::pcf::app::sm_policy::policy_storage>&
          policy_storage,
      pcf_event& ev);
  pcf_smpc(pcf_smpc const&) = delete;
  void operator=(pcf_smpc const&) = delete;

  virtual ~pcf_smpc();

  /**
   * @brief Handler for receiving create sm policy requests, as defined in
   * 3GPP TS 29.512 Chapter 4.2.2
   * The result depends on pre-configured policy rules based on supi, dnn,
   * snssai and default rules in that order
   *
   * @param context input: context from the request
   * @param decision output: policy decision based on context and local
   * provisioning
   * @return sm_policy::status_code
   */
  sm_policy::status_code create_sm_policy_handler(
      const oai::model::pcf::SmPolicyContextData& context,
      oai::model::pcf::SmPolicyDecision& decision, std::string& association_id,
      std::string& problem_details);

  /**
   * @brief Handler for deleting an existing SM policy association, as defined
   * in 3GPP TS 29.512 Chapter 4.2.5
   *
   * @param id The ID of the existing association, if not exist return
   * status_code::NOT_FOUND
   * @param delete_data input: delete data from the request
   * @param problem_details output: additional information in case of an error
   * @return sm_policy::status_code
   */
  sm_policy::status_code delete_sm_policy_handler(
      const std::string& id,
      const oai::model::pcf::SmPolicyDeleteData& delete_data,
      std::string& problem_details);

  /**
   * @brief Handler for getting an existing SM policy association, as defined in
   * 3GPP TS 29.512 Annex A
   *
   * @param id The ID of the existing association, if not exist return
   * status_code::NOT_FOUND
   * @param control output: The SmPolicyControl data
   * @param problem_details output: additional information in case of an
   * error
   * @return sm_policy::status_code
   */
  sm_policy::status_code get_sm_policy_handler(
      const std::string& id, oai::model::pcf::SmPolicyControl& control,
      std::string& problem_details);

  /**
   * @brief Handler for updating the policy decision based on the provided
   * update context, as define in 3GPP TS 29.512 Chapter 4.2.4
   *
   * @param id The ID of the existing association, if not exist return
   * status_code::NOT_FOUND
   * @param update_context input: The context of the update
   * @param decision output: The SmPolicyDecision
   * @param problem_details output: additional information in case of an error
   * @return sm_policy::status_code
   */
  sm_policy::status_code update_sm_policy_handler(
      const std::string& id,
      const oai::model::pcf::SmPolicyUpdateContextData& update_context,
      oai::model::pcf::SmPolicyDecision& decision,
      std::string& problem_details);

 private:
  oai::utils::uint_generator<uint32_t> m_association_id_generator;

  std::unordered_map<
      std::string, oai::pcf::app::sm_policy::individual_sm_association>
      m_associations;

  mutable std::shared_mutex m_associations_mutex;

  std::shared_ptr<oai::pcf::app::sm_policy::policy_storage> m_policy_storage;

  void handle_policy_change(
      const std::shared_ptr<oai::pcf::app::sm_policy::policy_decision>&
          decision);

  sm_policy::status_code send_sm_policy_control_update_notify(
      const oai::pcf::app::sm_policy::individual_sm_association& association);

  void handle_session_binding_request(
      const std::optional<std::string>& ipv4,
      const std::optional<std::string>& supi,
      const std::optional<std::string>& dnn,
      std::optional<std::string>& assoc_id,
      oai::model::pcf::SmPolicyDecision& decision);

  void handle_update_decision_request(
      std::optional<std::string>& association_id,
      oai::model::pcf::SmPolicyDecision& decision);

  // for Event Handling
  pcf_event& m_event_sub;
  bs2::connection m_sm_session_binding_connection;
  bs2::connection m_sm_update_decision_connection;
};
}  // namespace oai::pcf::app
#endif /* FILE_PCF_SM_POLICY_CONTROL_SEEN */
