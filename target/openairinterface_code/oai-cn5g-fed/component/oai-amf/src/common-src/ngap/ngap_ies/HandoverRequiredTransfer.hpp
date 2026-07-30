/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _HANDOVER_REQUIRED_TRANSFER_H_
#define _HANDOVER_REQUIRED_TRANSFER_H_

#include <optional>

#include "NgapIesStruct.hpp"
#include "QosFlowPerTnlInformation.hpp"
#include "SecurityResult.hpp"

extern "C" {
#include "Ngap_HandoverRequiredTransfer.h"
#include "Ngap_ProtocolIE-Field.h"
}

namespace oai::ngap {

class HandoverRequiredTransfer {
 public:
  HandoverRequiredTransfer();
  virtual ~HandoverRequiredTransfer();

  void setDirectForwardingPathAvailability(
      const Ngap_DirectForwardingPathAvailability_t&
          directForwardingPathAvailability);
  bool getDirectForwardingPathAvailability(
      long& directForwardingPathAvailability) const;
  std::optional<long> getDirectForwardingPathAvailability() const;

  int encode(uint8_t* buf, int bufSize);
  bool decode(uint8_t* buf, int bufSize);

 private:
  Ngap_HandoverRequiredTransfer_t* m_HandoverRquiredTransferIe;

  std::optional<Ngap_DirectForwardingPathAvailability_t>
      m_DirectForwardingPathAvailability;  // Optional
};

}  // namespace oai::ngap
#endif
