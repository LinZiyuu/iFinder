/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "dnn_policy_decision.hpp"
#include <sstream>

using namespace oai::model::pcf;
using namespace oai::pcf::app::sm_policy;
using namespace oai::pcf::app;

status_code dnn_policy_decision::decide(
    const SmPolicyContextData& context,
    oai::model::pcf::SmPolicyDecision& decision) const {
  if (context.getDnn() != m_dnn) {
    return status_code::CONTEXT_DENIED;
  }

  decision = m_decision;
  return status_code::CREATED;
}

std::string dnn_policy_decision::get_dnn() const {
  return m_dnn;
}

std::string dnn_policy_decision::to_string() const {
  std::stringstream ss;
  ss << "DNN: " << m_dnn << "\n";
  ss << " -- " << m_decision;
  return ss.str();
}

std::ostream& operator<<(
    std::ostream& os,
    const oai::pcf::app::sm_policy::dnn_policy_decision& storage) {
  return (os << storage.to_string());
}
