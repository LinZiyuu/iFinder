/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _QOS_RULES_H_
#define _QOS_RULES_H_

#include "QosRule.hpp"
#include "Type6NasIe.hpp"

constexpr uint8_t kQosRulesMinimumLength = 7;
constexpr uint8_t kQosRulesContentMinimumLength =
    kQosRulesMinimumLength - 3;  // Minimum length - 3 octets for IEI/Length
constexpr uint32_t kQosRulesMaximumLength = 65538;
constexpr auto kQosRulesIeName            = "QoS Rules";

namespace oai::nas {
using namespace oai::nas;
class QosRules : public Type6NasIe {
 public:
  QosRules();
  QosRules(uint8_t iei);
  QosRules(uint8_t iei, const std::vector<QosRule>& qos_rules);
  QosRules(const std::vector<QosRule>& qos_rules);
  virtual ~QosRules();

  int Encode(uint8_t* buf, int len) const;
  int Decode(const uint8_t* const buf, int len, bool is_iei);

  static std::string GetIeName() { return kQosRulesIeName; }

  void Set(const std::vector<QosRule>& rules);
  void Get(std::vector<QosRule>& rules) const;

  void AddQosRule(const QosRule& rule);

 private:
  std::vector<QosRule> qos_rules_;
};

}  // namespace oai::nas

#endif
