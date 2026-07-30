/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _QOS_FLOW_PER_TNL_INFORMATION_H_
#define _QOS_FLOW_PER_TNL_INFORMATION_H_

#include "AssociatedQosFlowList.hpp"
#include "UpTransportLayerInformation.hpp"

extern "C" {
#include "Ngap_QosFlowPerTNLInformation.h"
}

namespace oai::ngap {

class QosFlowPerTnlInformation {
 public:
  QosFlowPerTnlInformation();
  virtual ~QosFlowPerTnlInformation();

  void set(
      const UpTransportLayerInformation& upTransportLayerInformation,
      const AssociatedQosFlowList& associatedQosFlowList);
  void get(
      UpTransportLayerInformation& upTransportLayerInformation,
      AssociatedQosFlowList& associatedQosFlowList) const;

  bool encode(Ngap_QosFlowPerTNLInformation_t& qosFlowPerTnlInformation) const;
  bool decode(const Ngap_QosFlowPerTNLInformation_t& qosFlowPerTnlInformation);

 private:
  UpTransportLayerInformation m_UpTransportLayerInformation;  // Mandatory
  AssociatedQosFlowList m_AssociatedQosFlowList;              // Mandatory
};

}  // namespace oai::ngap

#endif
