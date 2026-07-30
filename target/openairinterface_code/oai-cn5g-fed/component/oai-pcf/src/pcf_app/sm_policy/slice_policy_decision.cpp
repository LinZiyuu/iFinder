/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "slice_policy_decision.hpp"
#include <sstream>

using namespace oai::model::pcf;
using namespace oai::pcf::app::sm_policy;
using namespace oai::pcf::app;
using namespace oai::model::common;

status_code slice_policy_decision::decide(
    const SmPolicyContextData& context, SmPolicyDecision& decision) const {
  if (context.getSliceInfo() != m_snssai) {
    return status_code::CONTEXT_DENIED;
  }

  decision = m_decision;
  return status_code::CREATED;
}

Snssai slice_policy_decision::get_snssai() const {
  return m_snssai;
}

std::string slice_policy_decision::to_string() const {
  std::stringstream ss;
  ss << "Slice: Sd: " << m_snssai.getSd()
     << " Sst: " << std::to_string(m_snssai.getSst()) << "\n";
  ss << " -- " << m_decision;
  return ss.str();
}

std::ostream& operator<<(
    std::ostream& os,
    const oai::pcf::app::sm_policy::slice_policy_decision& storage) {
  return (os << storage.to_string());
}
