/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _HANDOVER_REQUIRED_H_
#define _HANDOVER_REQUIRED_H_

#include <optional>

#include "Cause.hpp"
#include "GlobalGnbId.hpp"
#include "NgapUeMessage.hpp"
#include "PduSessionResourceListHandoverRqd.hpp"
#include "Tai.hpp"

extern "C" {
#include "Ngap_HandoverRequired.h"
#include "Ngap_TargetID.h"
}

namespace oai::ngap {

class HandoverRequiredMsg : public NgapUeMessage {
 public:
  HandoverRequiredMsg();
  virtual ~HandoverRequiredMsg();

  void initialize();

  void setAmfUeNgapId(const uint64_t& id) override;
  void setRanUeNgapId(const uint32_t& id) override;
  bool decode(Ngap_NGAP_PDU_t* ngapMsgPdu) override;

  Ngap_HandoverType_t getHandoverType() const;
  // TODO Setter

  Ngap_Cause_PR getChoiceOfCause() const;
  long getCauseValue() const;
  // TODO Setter

  bool getTargetId(GlobalGnbId& gnbId, Tai& tai) const;
  // TODO Setter

  bool getDirectForwardingPathAvailability(long& value) const;
  // TODO: Setter

  bool getPduSessionResourceList(PduSessionResourceListHandoverRqd& list) const;
  // TODO Setter

  OCTET_STRING_t getSourceToTargetTransparentContainer() const;
  // TODO Setter

 private:
  Ngap_HandoverRequired_t* m_HandoverRequiredIes;
  // AMF_UE_NGAP_ID (Mandatory)
  // RAN_UE_NGAP_ID (Mandatory)
  Ngap_HandoverType_t m_HandoverType;  // Mandatory
  Cause m_Cause;                       // Mandatory
  Ngap_TargetID_t m_TargetId;          // Mandatory
  std::optional<Ngap_DirectForwardingPathAvailability_t>
      m_DirectForwardingPathAvailability;                      // Optional
  PduSessionResourceListHandoverRqd m_PduSessionResourceList;  // Mandatory
  Ngap_SourceToTarget_TransparentContainer_t
      m_SourceToTargetTransparentContainer;  // Mandatory
};

}  // namespace oai::ngap

#endif
