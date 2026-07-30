/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_SETUP_UNSUCCESSFUL_TRANSFER_H_
#define _PDU_SESSION_RESOURCE_SETUP_UNSUCCESSFUL_TRANSFER_H_

#include "Cause.hpp"
#include "NgapIesStruct.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceSetupUnsuccessfulTransfer.h"
#include "Ngap_ProtocolIE-Field.h"
}

namespace oai::ngap {

class PduSessionResourceSetupUnSuccessfulTransferIE {
 public:
  PduSessionResourceSetupUnSuccessfulTransferIE();
  virtual ~PduSessionResourceSetupUnSuccessfulTransferIE();

  void setCauseRadioNetwork(e_Ngap_CauseRadioNetwork causeValue);
  void setCauseTransport(e_Ngap_CauseTransport causeValue);
  void setCauseNas(e_Ngap_CauseNas causeValue);
  void setCauseProtocol(e_Ngap_CauseProtocol causeValue);
  void setCauseMisc(e_Ngap_CauseMisc causeValue);
  long getChoiceOfCause() const;
  long getCause() const;

  int encode(uint8_t* buf, int buf_size);   // TODO: remove naked pointer
  bool decode(uint8_t* buf, int buf_size);  // TODO: remove naked pointer

 private:
  Ngap_PDUSessionResourceSetupUnsuccessfulTransfer_t*
      m_PduSessionResourceSetupUnsuccessfulTransferIe;

  Cause m_Cause;  // Mandatory
  // TODO: Criticality Diagnostics //Optional
};

}  // namespace oai::ngap
#endif
