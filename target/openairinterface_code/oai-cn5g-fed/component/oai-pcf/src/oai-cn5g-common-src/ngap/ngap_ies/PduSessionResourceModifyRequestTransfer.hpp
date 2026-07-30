/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_MODIFY_REQUEST_TRANSFER_H_
#define _PDU_SESSION_RESOURCE_MODIFY_REQUEST_TRANSFER_H_

#include <vector>

#include "NetworkInstance.hpp"
#include "NgapIesStruct.hpp"
#include "PduSessionAggregateMaximumBitRate.hpp"
#include "UlNgUUpTnlModifyList.hpp"
#include "QosFlowAddOrModifyRequestItem.hpp"
#include "QosFlowAddOrModifyRequestList.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceModifyRequestTransfer.h"
#include "Ngap_ProtocolIE-Field.h"
}

namespace oai::ngap {

class PduSessionResourceModifyRequestTransfer {
 public:
  PduSessionResourceModifyRequestTransfer();
  virtual ~PduSessionResourceModifyRequestTransfer(){};

  void setPduSessionAggregateMaximumBitRate(
      const long& bitRateDl, const long& bitRateUl);
  void setPduSessionAggregateMaximumBitRate(
      const PduSessionAggregateMaximumBitRate& maxBitRate);
  void getPduSessionAggregateMaximumBitRate(
      std::optional<PduSessionAggregateMaximumBitRate>& maxBitRate) const;

  void setUlNgUUpTnlModifyList(
      const UlNgUUpTnlModifyList& ulNgUUpTnlModifyList);
  void getUlNgUUpTnlModifyList(
      std::optional<UlNgUUpTnlModifyList>& ulNgUUpTnlModifyList) const;

  void setNetworkInstance(const long& value);
  bool getNetworkInstance(long& value) const;
  void getNetworkInstance(
      std::optional<NetworkInstance>& networkInstance) const;

  void setQosFlowAddOrModifyRequestList(
      const std::vector<QosFlowAddOrModifyRequestItem> list);
  void setQosFlowAddOrModifyRequestList(
      const QosFlowAddOrModifyRequestList& list);
  void getQosFlowAddOrModifyRequestList(
      std::optional<QosFlowAddOrModifyRequestList>& list) const;

  int encode(uint8_t* buf, int bufSize);
  bool decode(uint8_t* buf, int bufSize);

 private:
  Ngap_PDUSessionResourceModifyRequestTransfer_t* m_Ie;

  // PDU Session Aggregate Maximum Bit Rate (Optional)
  std::optional<PduSessionAggregateMaximumBitRate>
      m_PduSessionAggregateMaximumBitRateIe;
  // UL NG-U UP TNL Modify List (Optional 0..)
  std::optional<UlNgUUpTnlModifyList> m_UlNgUUpTnlModifyList;
  // Network Instance (Optional)
  std::optional<NetworkInstance> m_NetworkInstance;
  // QoS Flow Add or Modify Request List (Optional 0..)
  std::optional<QosFlowAddOrModifyRequestList> m_QosFlowAddOrModifyRequestList;
  // TODO: QoS Flow to Release List (Optional)
  // TODO: Additional UL NG-U UP TNL Information (Optional)
  // TODO: Common Network Instance (Optional)
  // TODO: Additional Redundant UL NG-U UP TNL Information (Optional)
  // TODO: Redundant Common Network Instance (Optional)
  // TODO: Redundant UL NG-U UP TNL Information (Optional)
  // TODO: Security Indication (Optional)

  void addPduSessionAggregateMaximumBitRate();
  void addQosFlowAddOrModifyRequestList();
};

}  // namespace oai::ngap
#endif
