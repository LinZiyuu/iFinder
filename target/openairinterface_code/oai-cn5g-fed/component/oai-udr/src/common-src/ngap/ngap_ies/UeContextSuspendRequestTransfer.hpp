/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _UE_CONTEXT_SUSPEND_REQUEST_TRANSFER_H_
#define _UE_CONTEXT_SUSPEND_REQUEST_TRANSFER_H_

#include "NgapIesStruct.hpp"

extern "C" {
#include "Ngap_ProtocolIE-Field.h"
#include "Ngap_UEContextSuspendRequestTransfer.h"
}

namespace oai::ngap {
class UeContextSuspendRequestTransfer {
 public:
  UeContextSuspendRequestTransfer();
  virtual ~UeContextSuspendRequestTransfer();

  int encode(uint8_t* buf, int bufSize);
  bool decode(uint8_t* buf, int bufSize);

 private:
  Ngap_UEContextSuspendRequestTransfer_t* m_UeContextSuspendRequestTransferIe;
  // TODO: Suspend Indicator (Optional)
};
}  // namespace oai::ngap

#endif
