/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PATH_SWITCH_REQUEST_TRANSFER_H_
#define _PATH_SWITCH_REQUEST_TRANSFER_H_

#include <memory>
#include <vector>

#include "NgapIesStruct.hpp"
#include "QosFlowAcceptedList.hpp"
#include "QosFlowListWithCause.hpp"
#include "UpTransportLayerInformation.hpp"

extern "C" {
#include "Ngap_PathSwitchRequestTransfer.h"
#include "Ngap_ProtocolIE-Field.h"
}

namespace oai::ngap {

class PathSwitchRequestTransfer {
 public:
  PathSwitchRequestTransfer();
  virtual ~PathSwitchRequestTransfer(){};

  void setDlNgUUpTnlInformation(
      const UpTransportLayerInformation& dlNgUUpTnlInformation);
  void getDlNgUUpTnlInformation(
      UpTransportLayerInformation& dlNgUUpTnlInformation) const;

  void setQosFlowAcceptedList(const std::vector<QosFlowAcceptedItem> list);
  void setQosFlowAcceptedList(const QosFlowAcceptedList& list);
  void getQosFlowAcceptedList(QosFlowAcceptedList& list) const;

  int encode(uint8_t* buf, int bufSize);
  bool decode(uint8_t* buf, int bufSize);

 private:
  Ngap_PathSwitchRequestTransfer_t* m_Ie;

  // DL NG-U UP TNL Information (Mandatory)
  UpTransportLayerInformation m_DlNgUUpTnlInformation;
  // TODO: DL NG-U TNL Information Reused (Optional)
  // TODO: User Plane Security Information (Optional)

  // QoS Flow Accepted List (Mandatory)
  QosFlowAcceptedList m_QosFlowAcceptedList;

  // TODO: Additional DL QoS Flow per TNL Information
  // TODO: Redundant DL NG-U UP TNL Information
  // TODO: Redundant DL NG-U UP TNL Information Reused
  // TODO: Additional Redundant DL QoS Flow per TNL Information
  // TODO: Used RSN Information
  // TODO: Global RAN Node ID of Secondary NG-RAN Node
};

}  // namespace oai::ngap
#endif
