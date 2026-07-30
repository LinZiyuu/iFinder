/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _UE_CONTEXT_RESUME_RESPONSE_TRANSFER_H_
#define _UE_CONTEXT_RESUME_RESPONSE_TRANSFER_H_

#include "NgapIesStruct.hpp"
#include "QosFlowListWithCause.hpp"

extern "C" {
#include "Ngap_ProtocolIE-Field.h"
#include "Ngap_UEContextResumeResponseTransfer.h"
}

namespace oai::ngap {
class UeContextResumeResponseTransfer {
 public:
  UeContextResumeResponseTransfer();
  virtual ~UeContextResumeResponseTransfer();

  void setQosFlowFailedToResumeList(
      const std::vector<QosFlowWithCauseItem> list);
  void setQosFlowFailedToResumeList(const QosFlowListWithCause& list);
  void getQosFlowFailedToResumeList(
      std::optional<QosFlowListWithCause>& list) const;

  int encode(uint8_t* buf, int bufSize);
  bool decode(uint8_t* buf, int bufSize);

 private:
  Ngap_UEContextResumeResponseTransfer_t* m_UeContextResumeResponseTransferIe;
  // QoS Flow Failed to Resume List (Optional)
  std::optional<QosFlowListWithCause> m_QosFlowFailedToResumeList;
};
}  // namespace oai::ngap

#endif
