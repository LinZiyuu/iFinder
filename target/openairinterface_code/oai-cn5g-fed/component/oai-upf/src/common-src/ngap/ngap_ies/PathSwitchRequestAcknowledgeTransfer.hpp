/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PATH_SWITCH_REQUEST_ACKNOWLEDGE_TRANSFER_H_
#define _PATH_SWITCH_REQUEST_ACKNOWLEDGE_TRANSFER_H_

#include <memory>
#include <vector>

#include "NgapIesStruct.hpp"
#include "QosFlowParametersList.hpp"
#include "UpTransportLayerInformation.hpp"

extern "C" {
#include "Ngap_PathSwitchRequestAcknowledgeTransfer.h"
#include "Ngap_ProtocolIE-Field.h"
}

namespace oai::ngap {

class PathSwitchRequestAcknowledgeTransfer {
 public:
  PathSwitchRequestAcknowledgeTransfer();
  virtual ~PathSwitchRequestAcknowledgeTransfer(){};

  void setUlNgUUpTnlInformation(
      const UpTransportLayerInformation& ulNgUUpTnlInformation);
  void getUlNgUUpTnlInformation(
      std::optional<UpTransportLayerInformation>& ulNgUUpTnlInformation) const;

  void setQosFlowParametersList(const std::vector<QosFlowParametersItem> list);
  void setQosFlowParametersList(const QosFlowParametersList& list);
  void getQosFlowParametersList(
      std::optional<QosFlowParametersList>& list) const;

  int encode(uint8_t* buf, int bufSize);
  bool decode(uint8_t* buf, int bufSize);

 private:
  Ngap_PathSwitchRequestAcknowledgeTransfer_t* m_Ie;

  // UL NG-U UP TNL Information (Optional)
  std::optional<UpTransportLayerInformation> m_UlNgUUpTnlInformation;

  // TODO: Security Indication
  // TODO: Additional NG-U UP TNL Information
  // TODO: Redundant UL NG-U UP TNL Information
  // TODO: Additional Redundant NG-U UP TNL Information

  // QoS Flow Parameters List (Optional 0..1)
  std::optional<QosFlowParametersList> m_QosFlowParametersList;
};

}  // namespace oai::ngap
#endif
