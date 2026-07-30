/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_MODIFY_INDICATION_TRANSFER_H_
#define _PDU_SESSION_RESOURCE_MODIFY_INDICATION_TRANSFER_H_

#include "NgapIesStruct.hpp"
#include "QosFlowPerTnlInformation.hpp"
#include "QosFlowPerTnlInformationList.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceModifyIndicationTransfer.h"
#include "Ngap_ProtocolIE-Field.h"
}

namespace oai::ngap {
class PduSessionResourceModifyIndicationTransfer {
 public:
  PduSessionResourceModifyIndicationTransfer();
  virtual ~PduSessionResourceModifyIndicationTransfer();

  void setDlQosFlowPerTnlInformation(
      const QosFlowPerTnlInformation& dlQosFlowPerTnlInformation);
  void getDlQosFlowPerTnlInformation(
      QosFlowPerTnlInformation& dlQosFlowPerTnlInformation) const;

  void setAdditionalDlQosFlowPerTnlInformation(
      const std::vector<QosFlowPerTnlInformationItem>& list);
  void setAdditionalDlQosFlowPerTnlInformation(
      const QosFlowPerTnlInformationList& list);
  void getAdditionalDlQosFlowPerTnlInformation(
      std::optional<QosFlowPerTnlInformationList>& list) const;

  int encode(uint8_t* buf, int bufSize);
  bool decode(uint8_t* buf, int bufSize);

 private:
  Ngap_PDUSessionResourceModifyIndicationTransfer_t* m_Ie;

  // DL QoS Flow per TNL Information (Mandatory)
  QosFlowPerTnlInformation m_DlQosFlowPerTnlInformation;
  // Additional DL QoS Flow per TNL Information (Optional)
  std::optional<QosFlowPerTnlInformationList>
      m_AdditionalDlQosFlowPerTnlInformation;

  // Secondary RAT Usage Information (Optional)
  // Security Result (Optional)
  //  Redundant DL QoS Flow per TNL Information (Optional)
  // Global RAN Node ID of Secondary NG-RAN Node (Optional)
};
}  // namespace oai::ngap

#endif
