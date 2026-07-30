/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _HANDOVER_COMMAND_TRANSFER_H_
#define _HANDOVER_COMMAND_TRANSFER_H_

#include "NgapIesStruct.hpp"
#include "QosFlowToBeForwardedList.hpp"
#include "UpTransportLayerInformation.hpp"

extern "C" {
#include "Ngap_HandoverCommandTransfer.h"
#include "Ngap_ProtocolIE-Field.h"
}

namespace oai::ngap {
class HandoverCommandTransfer {
 public:
  HandoverCommandTransfer();
  virtual ~HandoverCommandTransfer();

  void setDlForwardingUpTnlInformation(const GtpTunnel& upTransportLayerInfo);
  void setDlForwardingUpTnlInformation(
      const UpTransportLayerInformation& dlForwardingUpTnlInformation);
  void getDlForwardingUpTnlInformation(
      std::optional<UpTransportLayerInformation>& dlForwardingUpTnlInformation)
      const;

  void setQosFlowToBeForwardedList(
      const std::vector<QosFlowToBeForwardedItem_t>& list);
  void setQosFlowToBeForwardedList(
      const std::vector<QosFlowToBeForwardedItem> list);
  void setQosFlowToBeForwardedList(const QosFlowToBeForwardedList& list);
  void getQosFlowToBeForwardedList(
      std::optional<QosFlowToBeForwardedList>& list) const;

  int encode(uint8_t* buf, int bufSize) const;
  bool decode(uint8_t* buf, int bufSize);

 private:
  Ngap_HandoverCommandTransfer_t* m_Ie;

  // DL Forwarding UP TNL Information(Optional)
  std::optional<UpTransportLayerInformation> m_DlForwardingUpTnlInformation;
  // QoS Flow to be Forwarded List (Optional 0..1)
  std::optional<QosFlowToBeForwardedList> m_QosFlowToBeForwardedList;
  // TODO: Data Forwarding Response DRB List (Optional)
  // TODO: Additional DL Forwarding UP TNL Information (Optional)
  // TODO: UL Forwarding UP TNL Information (Optional)
  // TODO: Additional UL Forwarding UP TNL Information (Optional)
  // TODO: Data Forwarding Response E-RAB List (Optional)
  // TODO: QoS Flow Failed to Setup List (Optional)
};

}  // namespace oai::ngap
#endif
