/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _ADDITIONAL_QOS_FLOW_INFORMATION_H_
#define _ADDITIONAL_QOS_FLOW_INFORMATION_H_

extern "C" {
#include "Ngap_AdditionalQosFlowInformation.h"
}

namespace oai::ngap {

class AdditionalQosFlowInformation {
 public:
  AdditionalQosFlowInformation();
  AdditionalQosFlowInformation(e_Ngap_AdditionalQosFlowInformation value);
  virtual ~AdditionalQosFlowInformation();

  void set(e_Ngap_AdditionalQosFlowInformation value);
  bool get(e_Ngap_AdditionalQosFlowInformation& value) const;

  bool encode(Ngap_AdditionalQosFlowInformation_t&) const;
  bool decode(const Ngap_AdditionalQosFlowInformation_t&);

 private:
  long m_QosFlowInfo;
};

}  // namespace oai::ngap

#endif
