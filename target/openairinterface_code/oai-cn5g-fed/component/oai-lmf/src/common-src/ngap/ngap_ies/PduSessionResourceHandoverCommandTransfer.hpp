/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_HANDOVER_COMMAND_TRANSFER_H_
#define _PDU_SESSION_RESOURCE_HANDOVER_COMMAND_TRANSFER_H_

#include "NgapIesStruct.hpp"
#include "QosFlowToBeForwardedList.hpp"
#include "UpTransportLayerInformation.hpp"

extern "C" {
#include "Ngap_HandoverCommandTransfer.h"
#include "Ngap_ProtocolIE-Field.h"
}

namespace oai::ngap {
class PduSessionResourceHandoverCommandTransfer {
 public:
  PduSessionResourceHandoverCommandTransfer();
  virtual ~PduSessionResourceHandoverCommandTransfer();

  void setUPTransportLayerInformation(const GtpTunnel_t& upTransportLayerInfo);
  void setQosFlowToBeForwardedList(
      const std::vector<QosFlowToBeForwardedItem_t>& list);

  int encode(uint8_t* buf, int buf_size) const;  // TODO: remove naked pointer

 private:
  Ngap_HandoverCommandTransfer_t* m_HandoverCommandTransferIe;
  std::optional<UpTransportLayerInformation>
      m_DlForwardingUpTnlInformation;  // Optional
  std::optional<QosFlowToBeForwardedList>
      m_QosFlowToBeForwardedList;  // Optional (list 0..1)
  // TODO: Data Forwarding Response DRB List //Optional
  // TODO: Additional DL Forwarding UP TNL Information //Optional
  // TODO: UL Forwarding UP TNL Information //Optional
  // TODO: Additional UL Forwarding UP TNL Information //Optional
  // TODO: Data Forwarding Response E-RAB List //Optional
};

}  // namespace oai::ngap
#endif
