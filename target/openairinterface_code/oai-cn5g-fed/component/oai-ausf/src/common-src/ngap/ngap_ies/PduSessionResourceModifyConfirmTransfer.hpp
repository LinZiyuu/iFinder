/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_MODIFY_CONFIRM_TRANSFER_H_
#define _PDU_SESSION_RESOURCE_MODIFY_CONFIRM_TRANSFER_H_

#include <memory>
#include <vector>

#include "NgapIesStruct.hpp"
#include "QosFlowListWithCause.hpp"
#include "QosFlowModifyConfirmList.hpp"
#include "UpTransportLayerInformation.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceModifyConfirmTransfer.h"
#include "Ngap_ProtocolIE-Field.h"
}

namespace oai::ngap {

class PduSessionResourceModifyConfirmTransfer {
 public:
  PduSessionResourceModifyConfirmTransfer();
  virtual ~PduSessionResourceModifyConfirmTransfer(){};

  void setQosFlowModifyConfirmList(
      const std::vector<QosFlowModifyConfirmItem> list);
  void setQosFlowModifyConfirmList(const QosFlowModifyConfirmList& list);
  void getQosFlowModifyConfirmList(QosFlowModifyConfirmList& list) const;

  void setUlNgUUpTnlInformation(
      const UpTransportLayerInformation& ulNgUUpTnlInformation);
  void getUlNgUUpTnlInformation(
      UpTransportLayerInformation& ulNgUUpTnlInformation) const;

  void setQosFlowFailedToModifyList(
      const QosFlowListWithCause& qosFlowFailedToModifyList);
  void getQosFlowFailedToModifyList(
      std::optional<QosFlowListWithCause>& qosFlowFailedToModifyList) const;

  int encode(uint8_t* buf, int bufSize);
  bool decode(uint8_t* buf, int bufSize);

 private:
  Ngap_PDUSessionResourceModifyConfirmTransfer_t* m_Ie;

  // QoS Flow Modify Confirm List (Mandatory)
  QosFlowModifyConfirmList m_QosFlowModifyConfirmList;
  // UL NG-U UP TNL Information (Mandatory)
  UpTransportLayerInformation m_UlNgUUpTnlInformation;
  // TODO: Additional NG-U UP TNL Information (Optional)
  // QoS Flow Failed to Modify List (Optional)
  std::optional<QosFlowListWithCause> m_QosFlowFailedToModifyList;
  // Redundant UL NG-U UP TNL Information (Optional)
  // Additional Redundant NG-U UP TNL Information (Optional)
};

}  // namespace oai::ngap
#endif
