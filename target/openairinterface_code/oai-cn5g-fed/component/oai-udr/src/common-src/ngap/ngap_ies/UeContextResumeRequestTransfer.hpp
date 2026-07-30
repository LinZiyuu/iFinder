/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _UE_CONTEXT_RESUME_REQUEST_TRANSFER_H_
#define _UE_CONTEXT_RESUME_REQUEST_TRANSFER_H_

#include "NgapIesStruct.hpp"
#include "QosFlowListWithCause.hpp"

extern "C" {
#include "Ngap_ProtocolIE-Field.h"
#include "Ngap_UEContextResumeRequestTransfer.h"
}

namespace oai::ngap {
class UeContextResumeRequestTransfer {
 public:
  UeContextResumeRequestTransfer();
  virtual ~UeContextResumeRequestTransfer();

  void setQosFlowFailedToResumeList(
      const std::vector<QosFlowWithCauseItem> list);
  void setQosFlowFailedToResumeList(const QosFlowListWithCause& list);
  void getQosFlowFailedToResumeList(
      std::optional<QosFlowListWithCause>& list) const;

  int encode(uint8_t* buf, int bufSize);
  bool decode(uint8_t* buf, int bufSize);

 private:
  Ngap_UEContextResumeRequestTransfer_t* m_UeContextResumeRequestTransferIe;
  // QoS Flow Failed to Resume List (Optional)
  std::optional<QosFlowListWithCause> m_QosFlowFailedToResumeList;
};
}  // namespace oai::ngap

#endif
