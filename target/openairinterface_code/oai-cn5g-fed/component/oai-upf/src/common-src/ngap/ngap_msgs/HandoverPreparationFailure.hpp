/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _HANDOVER_PREPARATION_FAILURE_H_
#define _HANDOVER_PREPARATION_FAILURE_H_

#include "Cause.hpp"
#include "NgapUeMessage.hpp"

extern "C" {
#include "Ngap_CriticalityDiagnostics.h"
#include "Ngap_HandoverPreparationFailure.h"
}

namespace oai::ngap {

class HandoverPreparationFailure : public NgapUeMessage {
 public:
  HandoverPreparationFailure();
  virtual ~HandoverPreparationFailure();

  void initialize();
  void setAmfUeNgapId(const uint64_t& id) override;
  void setRanUeNgapId(const uint32_t& id) override;
  bool decode(Ngap_NGAP_PDU_t* ngapMsgPdu) override;

  void getCause(Cause& cause) const;
  void setCause(const Ngap_Cause_PR& causePresent, const long& value = 0);
  Ngap_Cause_PR getChoiceOfCause() const;

 private:
  Ngap_HandoverPreparationFailure_t* m_HOPreparationFailureIes;
  // AMF_UE_NGAP_ID (Mandatory)
  // RAN_UE_NGAP_ID (Mandatory)
  Cause m_Cause;                                            // Mandatory
  Ngap_CriticalityDiagnostics_t* m_CriticalityDiagnostics;  // Optional
  // TODO: Target to Source Failure Transparent Container (Optional,
  // Rel 16.14.0)
};

}  // namespace oai::ngap

#endif
