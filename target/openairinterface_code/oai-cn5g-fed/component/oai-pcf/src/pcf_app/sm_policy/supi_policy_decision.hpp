/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_SUPI_POLICY_DECISION_SEEN
#define FILE_SUPI_POLICY_DECISION_SEEN

#include "policy_decision.hpp"
#include "SmPolicyContextData.h"
#include "SmPolicyDecision.h"
#include "pcf_smpc_status_code.hpp"

#include <string>

namespace oai::pcf::app::sm_policy {
/**
 * @brief Policy Decision based on SUPI.
 *
 */
class supi_policy_decision : public oai::pcf::app::sm_policy::policy_decision {
 public:
  explicit supi_policy_decision(
      const std::string& supi,
      const oai::model::pcf::SmPolicyDecision& decision)
      : policy_decision(decision) {
    m_supi = supi;
  }

  ~supi_policy_decision() override = default;

  /**
   * @brief Decides based on context on a policy and the DNN information. In
   * case the return code is != CREATED, the decision reference may be undefined
   *
   * @param context input: The context of the individual sm policy association
   * @param decision output: The decision based on the context
   * @return oai::pcf::app::sm_policy::status_code   CREATED in case of
   * success
   */
  [[nodiscard]] oai::pcf::app::sm_policy::status_code decide(
      const oai::model::pcf::SmPolicyContextData& context,
      oai::model::pcf::SmPolicyDecision& decision) const override;

  /**
   * @brief Get the supi object
   *
   * @return std::string
   */
  [[nodiscard]] std::string get_supi() const;

  [[nodiscard]] std::string to_string() const override;

 private:
  std::string m_supi;
};
}  // namespace oai::pcf::app::sm_policy

std::ostream& operator<<(
    std::ostream& os,
    const oai::pcf::app::sm_policy::supi_policy_decision& storage);

#endif
