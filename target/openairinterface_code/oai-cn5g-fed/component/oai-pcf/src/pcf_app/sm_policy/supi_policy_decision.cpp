/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "supi_policy_decision.hpp"
#include <sstream>

using namespace oai::model::pcf;
using namespace oai::pcf::app::sm_policy;
using namespace oai::pcf::app;

status_code supi_policy_decision::decide(
    const SmPolicyContextData& context, SmPolicyDecision& decision) const {
  if (context.getSupi() != m_supi) {
    return status_code::CONTEXT_DENIED;
  }

  decision = m_decision;
  return status_code::CREATED;
}

std::string supi_policy_decision::get_supi() const {
  return m_supi;
}

std::string supi_policy_decision::to_string() const {
  std::stringstream ss;
  ss << "SUPI: " << m_supi << "\n";
  ss << " -- " << m_decision;
  return ss.str();
}

std::ostream& operator<<(
    std::ostream& os,
    const oai::pcf::app::sm_policy::supi_policy_decision& storage) {
  return (os << storage.to_string());
}
