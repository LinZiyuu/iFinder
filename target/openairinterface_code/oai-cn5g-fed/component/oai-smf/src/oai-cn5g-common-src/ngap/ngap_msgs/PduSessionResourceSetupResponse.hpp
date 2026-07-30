/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_SETUP_RESPONSE_H_
#define _PDU_SESSION_RESOURCE_SETUP_RESPONSE_H_

#include "NgapUeMessage.hpp"
#include "PduSessionResourceFailedToSetupListSURes.hpp"
#include "PduSessionResourceSetupListSURes.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceSetupResponse.h"
}

namespace oai::ngap {

class PduSessionResourceSetupResponseMsg : public NgapUeMessage {
 public:
  PduSessionResourceSetupResponseMsg();
  virtual ~PduSessionResourceSetupResponseMsg();

  void initialize();

  void setAmfUeNgapId(const uint64_t& id) override;
  void setRanUeNgapId(const uint32_t& id) override;
  bool decode(Ngap_NGAP_PDU_t* ngapMsgPdu) override;

  void setPduSessionResourceSetupResponseList(
      const std::vector<PDUSessionResourceSetupResponseItem_t>& list);
  bool getPduSessionResourceSetupResponseList(
      std::vector<PDUSessionResourceSetupResponseItem_t>& list) const;

  void setPduSessionResourceFailedToSetupList(
      const std::vector<PDUSessionResourceFailedToSetupItem_t>& list);
  bool getPduSessionResourceFailedToSetupList(
      std::vector<PDUSessionResourceFailedToSetupItem_t>& list) const;

 private:
  Ngap_PDUSessionResourceSetupResponse_t* m_PduSessionResourceSetupResponseIes;
  std::optional<PduSessionResourceSetupListSURes>
      m_PduSessionResourceSetupResponseList;  // Optional
  std::optional<PduSessionResourceFailedToSetupListSURes>
      m_PduSessionResourceFailedToSetupResponseList;  // Optional
  // TODO: Criticality Diagnostics (Optional)
};

}  // namespace oai::ngap
#endif
