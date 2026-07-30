/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_HANDOVER_REQUIRED_TRANSFER_H_
#define _PDU_SESSION_RESOURCE_HANDOVER_REQUIRED_TRANSFER_H_

#include <optional>

#include "NgapIesStruct.hpp"
#include "QosFlowPerTnlInformation.hpp"
#include "SecurityResult.hpp"

extern "C" {
#include "Ngap_HandoverRequiredTransfer.h"
#include "Ngap_ProtocolIE-Field.h"
}

namespace oai::ngap {

class PduSessionResourceHandoverRequiredTransfer {
 public:
  PduSessionResourceHandoverRequiredTransfer();
  virtual ~PduSessionResourceHandoverRequiredTransfer();

  void setDirectForwardingPathAvailability(
      const Ngap_DirectForwardingPathAvailability_t&
          directForwardingPathAvailability);
  bool getDirectForwardingPathAvailability(
      long& directForwardingPathAvailability) const;

  int encode(uint8_t* buf, int buf_size);   // TODO: remove naked pointer
  bool decode(uint8_t* buf, int buf_size);  // TODO: remove naked pointer

 private:
  Ngap_HandoverRequiredTransfer_t* m_HandoverRquiredTransferIe;
  std::optional<Ngap_DirectForwardingPathAvailability_t>
      m_DirectForwardingPathAvailability;  // Optional
};

}  // namespace oai::ngap
#endif
