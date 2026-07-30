/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef PDU_SESSION_RESOURCE_MODIFY_RESPONSE_H_
#define PDU_SESSION_RESOURCE_MODIFY_RESPONSE_H_

#include "NgapUeMessage.hpp"
#include "PduSessionResourceModifyListModRes.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceModifyResponse.h"
}

namespace oai::ngap {

class PduSessionResourceModifyResponseMsg : public NgapUeMessage {
 public:
  PduSessionResourceModifyResponseMsg();
  virtual ~PduSessionResourceModifyResponseMsg();

  void initialize();

  void setAmfUeNgapId(const uint64_t& id) override;
  void setRanUeNgapId(const uint32_t& id) override;
  bool decode(Ngap_NGAP_PDU_t* ngapMsgPdu) override;

  void setPduSessionResourceModifyResponseList(
      const std::vector<PDUSessionResourceModifyResponseItem_t>& list);
  bool getPduSessionResourceModifyResponseList(
      std::vector<PDUSessionResourceModifyResponseItem_t>& list) const;

 private:
  Ngap_PDUSessionResourceModifyResponse_t* pduSessionResourceModifyResponseIes;

  std::optional<PduSessionResourceModifyListModRes>
      m_PduSessionResourceModifyList;  // Optional
  // TODO: PDUSessionResourceFailedToModifyListModRes (Optional)
  // TODO: User Location Information (Optional)
  // TODO: Criticality Diagnostics (Optional)
};

}  // namespace oai::ngap
#endif
