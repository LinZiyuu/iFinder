/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _HANDOVER_RESOURCE_ALLOCATION_UNSUCCESSFUL_TRANSFER_H_
#define _HANDOVER_RESOURCE_ALLOCATION_UNSUCCESSFUL_TRANSFER_H_

#include "Cause.hpp"
#include "NgapIesStruct.hpp"

extern "C" {
#include "Ngap_HandoverResourceAllocationUnsuccessfulTransfer.h"
#include "Ngap_ProtocolIE-Field.h"
}

namespace oai::ngap {

class HandoverResourceAllocationUnsuccessfulTransfer {
 public:
  HandoverResourceAllocationUnsuccessfulTransfer();
  virtual ~HandoverResourceAllocationUnsuccessfulTransfer();

  void setCauseRadioNetwork(e_Ngap_CauseRadioNetwork causeValue);
  void setCauseTransport(e_Ngap_CauseTransport causeValue);
  void setCauseNas(e_Ngap_CauseNas causeValue);
  void setCauseProtocol(e_Ngap_CauseProtocol causeValue);
  void setCauseMisc(e_Ngap_CauseMisc causeValue);

  long getChoiceOfCause() const;
  long getCause() const;

  int encode(uint8_t* buf, int bufSize);
  bool decode(uint8_t* buf, int bufSize);

 private:
  Ngap_HandoverResourceAllocationUnsuccessfulTransfer_t*
      m_HandoverResourceAllocationUnsuccessfulTransferIe;

  Cause m_CauseValue;  // Mandatory
  // TODO: Secondary RAT Usage Information
};

}  // namespace oai::ngap
#endif
