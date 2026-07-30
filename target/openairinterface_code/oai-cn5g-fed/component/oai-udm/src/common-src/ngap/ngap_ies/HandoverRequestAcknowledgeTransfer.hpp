/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _HANDOVER_REQUEST_ACKNOWLEDGE_TRANSFER_H_
#define _HANDOVER_REQUEST_ACKNOWLEDGE_TRANSFER_H_

#include "NgapIesStruct.hpp"
#include "QosFlowItemWithDataForwarding.hpp"
#include "QosFlowListWithDataForwarding.hpp"
#include "QosFlowPerTnlInformation.hpp"
#include "SecurityResult.hpp"
#include "UpTransportLayerInformation.hpp"

extern "C" {
#include "Ngap_HandoverRequestAcknowledgeTransfer.h"
#include "Ngap_ProtocolIE-Field.h"
}

namespace oai::ngap {
class HandoverRequestAcknowledgeTransfer {
 public:
  HandoverRequestAcknowledgeTransfer();
  virtual ~HandoverRequestAcknowledgeTransfer();

  // DL NG-U UP TNL Information
  void setDlNgUUpTnlInformation(
      const UpTransportLayerInformation& dlNgUUpTnlInformation);
  void getDlNgUUpTnlInformation(
      UpTransportLayerInformation& dlNgUUpTnlInformation) const;

  // DL Forwarding UP TNL Information
  void setDlForwardingUpTnlInformation(
      const UpTransportLayerInformation& dlForwardingUpTnlInformation);
  void getDlForwardingUpTnlInformation(
      std::optional<UpTransportLayerInformation>& dlForwardingUpTnlInformation)
      const;
  bool getDlForwardingUpTnlInformation(GtpTunnel*& upTnlInfo);

  // TODO: Security Result

  // QoS Flow Setup Response List
  void setQosFlowSetupResponseList(
      const std::vector<QosFlowItemWithDataForwarding>& list);
  void setQosFlowSetupResponseList(const QosFlowListWithDataForwarding& list);
  void getQosFlowSetupResponseList(
      std::vector<QosFlowItemWithDataForwarding>& list) const;
  void getQosFlowSetupResponseList(QosFlowListWithDataForwarding& list) const;

  // TODO: QoS Flow Failed to Setup List
  // TODO: Data Forwarding Response DRB List
  // TODO: Additional DL UP TNL Information for HO List
  // TODO: UL Forwarding UP TNL Information
  // TODO: Additional UL Forwarding UP TNL Information
  // TODO: Data Forwarding Response E-RAB List
  // TODO: Redundant DL NG-U UP TNL Information
  // TODO: Used RSN Information
  // TODO: Global RAN Node ID of Secondary NG-RAN Node

  int encode(uint8_t* buf, int bufSize);
  bool decode(uint8_t* buf, int bufSize);

 private:
  Ngap_HandoverRequestAcknowledgeTransfer_t*
      m_HandoverRequestAcknowledegTransferIe;
  // DL NG-U UP TNL Information (Mandatory)
  UpTransportLayerInformation m_DlNgUUpTnlInformation;
  // DL Forwarding UP TNL Information (Optional)
  std::optional<UpTransportLayerInformation> m_DlForwardingUpTnlInformation;
  // TODO: Security Result (Optional)
  // QoS Flow Setup Response List (Mandatory)
  QosFlowListWithDataForwarding m_QosFlowSetupResponseList;
  // TODO: QoS Flow Failed to Setup List (Optional)
  // TODO: Data Forwarding Response DRB List (Optional)
  // TODO: Additional DL UP TNL Information for HO List //Range 0..1
  // TODO: UL Forwarding UP TNL Information (Optional)
  // TODO: Additional UL Forwarding UP TNL Information (Optional)
  // TODO: Data Forwarding Response E-RAB List (Optional)
  // TODO: Redundant DL NG-U UP TNL Information (Optional)
  // TODO: Used RSN Information (Optional)
  // TODO: Global RAN Node ID of Secondary NG-RAN Node (Optional)
};
}  // namespace oai::ngap

#endif
