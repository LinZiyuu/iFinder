/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "individual_sm_association.hpp"

using namespace oai::model::pcf;
using namespace oai::pcf::app::sm_policy;

const SmPolicyContextData&
individual_sm_association::get_sm_policy_context_data() const {
  return m_context;
}

const SmPolicyDecision& individual_sm_association::get_sm_policy_decision_dto()
    const {
  return m_decision.get_sm_policy_decision();
}

const void individual_sm_association::set_sm_policy_decision(
    oai::model::pcf::SmPolicyDecision& new_decision) {
  m_decision.set_sm_policy_decision(new_decision);
}

std::string individual_sm_association::get_id() const {
  return m_id;
}

oai::pcf::app::sm_policy::status_code
individual_sm_association::redecide_policy(
    const SmPolicyUpdateContextData& update_data,
    SmPolicyDecision& new_decision, std::string& problem_details) {
  return m_decision.redecide(
      m_context, update_data, new_decision, problem_details);
}

oai::pcf::app::sm_policy::status_code individual_sm_association::decide_policy(
    SmPolicyDecision& decision) {
  return m_decision.decide(m_context, decision);
}
