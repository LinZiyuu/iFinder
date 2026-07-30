/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_RELEASE_RESPONSE_TRANSFER_H_
#define _PDU_SESSION_RESOURCE_RELEASE_RESPONSE_TRANSFER_H_

#include "Cause.hpp"
#include "NgapIesStruct.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceReleaseResponseTransfer.h"
#include "Ngap_ProtocolIE-Field.h"
}

namespace oai::ngap {

class PduSessionResourceReleaseResponseTransfer {
 public:
  PduSessionResourceReleaseResponseTransfer();
  virtual ~PduSessionResourceReleaseResponseTransfer();

  // TODO: Secondary RAT Usage Information (Optional)

  int encode(uint8_t* buf, int bufSize);
  bool decode(uint8_t* buf, int bufSize);

 private:
  Ngap_PDUSessionResourceReleaseResponseTransfer_t*
      m_PduSessionResourceReleaseResponseTransferIe;

  // TODO: Secondary RAT Usage Information (Optional)
};

}  // namespace oai::ngap
#endif
