/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _QOS_FLOW_DESCRIPTIONS_H_
#define _QOS_FLOW_DESCRIPTIONS_H_

#include "QosFlowDescription.hpp"
#include "Type6NasIe.hpp"

constexpr uint8_t kQosFlowDescriptionsMinimumLength = 6;
constexpr uint8_t kQosFlowDescriptionsContentMinimumLength =
    kQosFlowDescriptionsMinimumLength -
    3;  // Minimum length - 3 octets for IEI/Length
constexpr uint32_t kQosFlowDescriptionsMaximumLength = 65538;
constexpr auto kQosFlowDescriptionsIeName            = "QoS Flow Descriptions";

namespace oai::nas {
class QosFlowDescriptions : public Type6NasIe {
 public:
  QosFlowDescriptions();
  QosFlowDescriptions(uint8_t iei);
  QosFlowDescriptions(
      uint8_t iei, const std::vector<QosFlowDescription>& qos_rules);
  QosFlowDescriptions(const std::vector<QosFlowDescription>& qos_rules);
  virtual ~QosFlowDescriptions();

  int Encode(uint8_t* buf, int len) const;
  int Decode(const uint8_t* const buf, int len, bool is_iei);

  static std::string GetIeName() { return kQosFlowDescriptionsIeName; }

  void Set(const std::vector<QosFlowDescription>& qos_flow_descriptions);
  void Get(std::vector<QosFlowDescription>& qos_flow_descriptions) const;

  void AddQosFlowDescription(const QosFlowDescription& qos_flow_description);

 private:
  std::vector<QosFlowDescription> qos_flow_descriptions_;
};

}  // namespace oai::nas

#endif
