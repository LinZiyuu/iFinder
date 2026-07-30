/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _QOS_FLOW_PER_TNL_INFORMATION_ITEM_H_
#define _QOS_FLOW_PER_TNL_INFORMATION_ITEM_H_

#include "QosFlowPerTnlInformation.hpp"

extern "C" {
#include "Ngap_QosFlowPerTNLInformationItem.h"
}

namespace oai::ngap {

class QosFlowPerTnlInformationItem {
 public:
  QosFlowPerTnlInformationItem();
  virtual ~QosFlowPerTnlInformationItem();

  void set(const QosFlowPerTnlInformation& qosFlowPerTnlInformation);
  void get(QosFlowPerTnlInformation& qosFlowPerTnlInformation) const;

  bool encode(
      Ngap_QosFlowPerTNLInformationItem_t& qosFlowPerTnlInformationItem) const;
  bool decode(
      const Ngap_QosFlowPerTNLInformationItem_t& qosFlowPerTnlInformationItem);

 private:
  QosFlowPerTnlInformation m_QosFlowPerTnlInformation;  // Mandatory
  // TODO: Ngap_ProtocolExtensionContainer
};

}  // namespace oai::ngap

#endif
