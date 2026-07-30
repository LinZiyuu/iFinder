/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_SLICE_POLICY_DECISION_SEEN
#define FILE_SLICE_POLICY_DECISION_SEEN

#include "policy_decision.hpp"
#include "SmPolicyContextData.h"
#include "SmPolicyDecision.h"
#include "pcf_smpc_status_code.hpp"
#include "Snssai.h"

namespace oai::pcf::app::sm_policy {
/**
 * @brief Policy Decision based on slice.
 *
 */
class slice_policy_decision : public oai::pcf::app::sm_policy::policy_decision {
 public:
  explicit slice_policy_decision(
      const oai::model::common::Snssai& snssai,
      const oai::model::pcf::SmPolicyDecision& decision)
      : policy_decision(decision) {
    m_snssai = snssai;
  }

  ~slice_policy_decision() override = default;

  /**
   * @brief Decides based on context on a policy and the snssai information. In
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
   * @brief Get the snssai object
   *
   * @return oai::model::pcf::Snssai
   */
  [[nodiscard]] oai::model::common::Snssai get_snssai() const;

  [[nodiscard]] std::string to_string() const override;

 private:
  oai::model::common::Snssai m_snssai;
};
}  // namespace oai::pcf::app::sm_policy

std::ostream& operator<<(
    std::ostream& os,
    const oai::pcf::app::sm_policy::slice_policy_decision& storage);

#endif
