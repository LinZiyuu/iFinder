/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _HANDOVER_REQUEST_ACK_H_
#define _HANDOVER_REQUEST_ACK_H_

#include "NgapUeMessage.hpp"
#include "PduSessionResourceAdmittedList.hpp"
#include "PduSessionResourceFailedToSetupListHoAck.hpp"

extern "C" {
#include "Ngap_HandoverRequestAcknowledge.h"
}

namespace oai::ngap {

class HandoverRequestAck : public NgapUeMessage {
 public:
  HandoverRequestAck();
  virtual ~HandoverRequestAck();

  void initialize();

  void setAmfUeNgapId(const uint64_t& id) override;
  void setRanUeNgapId(const uint32_t& id) override;
  bool decode(Ngap_NGAP_PDU_t* ngapMsgPdu) override;

  void setPduSessionResourceAdmittedList(
      const PduSessionResourceAdmittedList& admittedList);
  bool getPduSessionResourceAdmittedList(
      std::vector<PDUSessionResourceAdmittedItem_t>& list) const;

  void setPduSessionResourceFailedToSetupListHOAck(
      const PduSessionResourceFailedToSetupListHoAck& list);
  void setPduSessionResourceFailedToSetupListHOAck(
      const std::vector<PduSessionResourceItem>& list);
  bool getPduSessionResourceFailedToSetupListHOAck(
      std::vector<PduSessionResourceItem>& list) const;

  void setTargetToSourceTransparentContainer(
      const OCTET_STRING_t& targetTosource);
  OCTET_STRING_t getTargetToSourceTransparentContainer() const;

 private:
  Ngap_HandoverRequestAcknowledge_t* m_HandoverRequestAckIes;
  // AMF_UE_NGAP_ID (Mandatory)
  // RAN_UE_NGAP_ID (Mandatory)
  PduSessionResourceAdmittedList m_PduSessionResourceAdmittedList;  // Mandatory
  std::optional<PduSessionResourceFailedToSetupListHoAck>
      m_PduSessionResourceFailedToSetupList;                // Optional
  OCTET_STRING_t m_TargetToSourceTransparentContainer;      // TODO: Mandatory
  Ngap_CriticalityDiagnostics_t* m_CriticalityDiagnostics;  // TODO: Optional
  // TODO: NPN Access Information (Optional, Rel 16.14.0)
};

}  // namespace oai::ngap

#endif
