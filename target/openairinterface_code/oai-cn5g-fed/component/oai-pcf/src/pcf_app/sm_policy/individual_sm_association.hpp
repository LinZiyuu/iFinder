/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_INDIVIDUAL_SM_ASSOCIATION_SEEN
#define FILE_INDIVIDUAL_SM_ASSOCIATION_SEEN

#include "SmPolicyContextData.h"
#include "SmPolicyDecision.h"
#include "policy_decision.hpp"

#include <memory.h>

namespace oai::pcf::app::sm_policy {

class individual_sm_association {
 public:
  explicit individual_sm_association(
      const oai::model::pcf::SmPolicyContextData& context,
      const oai::pcf::app::sm_policy::policy_decision& decision,
      const std::string& id)
      : m_decision(decision) {
    m_context = context;
    m_id      = id;
  }

  virtual ~individual_sm_association() = default;

  [[nodiscard]] virtual const oai::model::pcf::SmPolicyContextData&
  get_sm_policy_context_data() const;

  [[nodiscard]] virtual const oai::model::pcf::SmPolicyDecision&
  get_sm_policy_decision_dto() const;

  [[nodiscard]] virtual const void set_sm_policy_decision(
      oai::model::pcf::SmPolicyDecision& new_decision);

  [[nodiscard]] virtual oai::pcf::app::sm_policy::status_code redecide_policy(
      const oai::model::pcf::SmPolicyUpdateContextData& update_data,
      oai::model::pcf::SmPolicyDecision& new_decision,
      std::string& problem_details);

  [[nodiscard]] virtual oai::pcf::app::sm_policy::status_code decide_policy(
      oai::model::pcf::SmPolicyDecision& decision);

  [[nodiscard]] virtual std::string get_id() const;

 private:
  oai::model::pcf::SmPolicyContextData m_context;
  oai::pcf::app::sm_policy::policy_decision m_decision;
  std::string m_id;
};
}  // namespace oai::pcf::app::sm_policy
#endif
