/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_POLICY_DECISION_SEEN
#define FILE_POLICY_DECISION_SEEN

#include "SmPolicyContextData.h"
#include "SmPolicyDecision.h"
#include "SmPolicyUpdateContextData.h"
#include "pcf_smpc_status_code.hpp"

namespace oai::pcf::app::sm_policy {

/**
 * @brief Base class for policy decisions, also acts as default policy
 *
 */
class policy_decision {
 public:
  explicit policy_decision(const oai::model::pcf::SmPolicyDecision& decision) {
    m_decision = decision;
  }

  policy_decision(const policy_decision& other) {
    m_decision = other.m_decision;
  }

  /**
   * @brief Decides based on context on a policy. In case the return code is !=
   * CREATED, the decision reference may be undefined
   *
   * @param context input: The context of the individual sm policy association
   * @param decision output: The decision based on the context
   * @return oai::pcf::app::sm_policy::status_code   CREATED in case of
   * success
   */
  [[nodiscard]] virtual oai::pcf::app::sm_policy::status_code decide(
      const oai::model::pcf::SmPolicyContextData& context,
      oai::model::pcf::SmPolicyDecision& decision) const;

  /**
   * @brief Redecides based on the original context, original decision and
   * creates a new decision. The new_decision contains a complete new policy
   * decision
   *
   * @param original_context The context of the create request and/or
   * previous update requests, is changed according to updated values in
   * update_data
   * @param update_data input: The data from the update
   * @param new_decision output: the diff to the old decision (TODO currently no
   * diff, but whole object)
   * @param problem_details output: Error information
   * @return oai::pcf::app::sm_policy::status_code OK in case of successful
   * update
   */
  [[nodiscard]] virtual oai::pcf::app::sm_policy::status_code redecide(
      oai::model::pcf::SmPolicyContextData& original_context,
      const oai::model::pcf::SmPolicyUpdateContextData& update_data,
      oai::model::pcf::SmPolicyDecision& new_decision,
      std::string& problem_details);

  virtual ~policy_decision() = default;

  [[nodiscard]] virtual const oai::model::pcf::SmPolicyDecision&
  get_sm_policy_decision() const;

  [[nodiscard]] virtual const void set_sm_policy_decision(
      oai::model::pcf::SmPolicyDecision& decision);

  [[nodiscard]] virtual std::string to_string() const;

 protected:
  oai::pcf::app::sm_policy::status_code handle_plmn_change(
      oai::model::pcf::SmPolicyContextData& orig_context,
      const oai::model::pcf::SmPolicyUpdateContextData& update,
      std::string& problem_details);

  oai::pcf::app::sm_policy::status_code handle_access_type_change(
      oai::model::pcf::SmPolicyContextData& orig_context,
      const oai::model::pcf::SmPolicyUpdateContextData& update,
      std::string& problem_details);

  oai::pcf::app::sm_policy::status_code handle_ip_address_change(
      oai::model::pcf::SmPolicyContextData& orig_context,
      const oai::model::pcf::SmPolicyUpdateContextData& update,
      std::string& problem_details);

  oai::pcf::app::sm_policy::status_code handle_rat_type_change(
      oai::model::pcf::SmPolicyContextData& orig_context,
      const oai::model::pcf::SmPolicyUpdateContextData& update,
      std::string& problem_details);

  oai::model::pcf::SmPolicyDecision m_decision;
};
}  // namespace oai::pcf::app::sm_policy

std::ostream& operator<<(
    std::ostream& os, const oai::pcf::app::sm_policy::policy_decision& storage);

#endif
