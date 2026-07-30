/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef PDU_SESSION_RESOURCE_MODIFY_REQUEST_H_
#define PDU_SESSION_RESOURCE_MODIFY_REQUEST_H_

#include "NgapUeMessage.hpp"
#include "PduSessionResourceModifyListModReq.hpp"
#include "RanPagingPriority.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceModifyRequest.h"
}

namespace oai::ngap {

class PduSessionResourceModifyRequestMsg : public NgapUeMessage {
 public:
  PduSessionResourceModifyRequestMsg();
  virtual ~PduSessionResourceModifyRequestMsg();

  void initialize();

  void setAmfUeNgapId(const uint64_t& id) override;
  void setRanUeNgapId(const uint32_t& id) override;
  bool decode(Ngap_NGAP_PDU_t* ngapMsgPdu) override;

  void setRanPagingPriority(const uint32_t& priority);
  int getRanPagingPriority() const;

  void setNasPdu(const bstring& pdu);
  bool getNasPdu(bstring& pdu) const;

  void setPduSessionResourceModifyRequestList(
      const std::vector<PDUSessionResourceModifyRequestItem_t>& list);
  bool getPduSessionResourceModifyRequestList(
      std::vector<PDUSessionResourceModifyRequestItem_t>& list) const;

 private:
  Ngap_PDUSessionResourceModifyRequest_t* m_PduSessionResourceModifyRequestIes;

  RanPagingPriority* m_RanPagingPriority;  // Optional
  PduSessionResourceModifyListModReq
      m_PduSessionResourceModifyList;  // Mandatory
};

}  // namespace oai::ngap
#endif
