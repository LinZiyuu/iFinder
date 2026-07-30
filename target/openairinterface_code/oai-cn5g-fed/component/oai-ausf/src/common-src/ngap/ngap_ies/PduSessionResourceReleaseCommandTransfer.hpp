/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_RELEASE_COMMAND_TRANSFER_H_
#define _PDU_SESSION_RESOURCE_RELEASE_COMMAND_TRANSFER_H_

#include "Cause.hpp"
#include "NgapIesStruct.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceReleaseCommandTransfer.h"
#include "Ngap_ProtocolIE-Field.h"
}

namespace oai::ngap {

class PduSessionResourceReleaseCommandTransfer {
 public:
  PduSessionResourceReleaseCommandTransfer();
  virtual ~PduSessionResourceReleaseCommandTransfer();

  void setCause(const Cause& cause);
  void setCauseRadioNetwork(e_Ngap_CauseRadioNetwork causeValue);
  void setCauseTransport(e_Ngap_CauseTransport causeValue);
  void setCauseNas(e_Ngap_CauseNas causeValue);
  void setCauseProtocol(e_Ngap_CauseProtocol causeValue);
  void setCauseMisc(e_Ngap_CauseMisc causeValue);

  long getChoiceOfCause() const;
  long getCause() const;

  int encode(uint8_t* buf, int bufSize);
  void encode2NewBuffer(uint8_t*& buf, int& encoded_size);
  bool decode(uint8_t* buf, int bufSize);

 private:
  Ngap_PDUSessionResourceReleaseCommandTransfer_t*
      m_PduSessionResourceReleaseCommandTransferIe;

  Cause m_CauseValue;  // Mandatory
};

}  // namespace oai::ngap
#endif
