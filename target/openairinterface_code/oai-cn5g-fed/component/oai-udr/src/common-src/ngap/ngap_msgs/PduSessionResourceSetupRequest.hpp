/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_SETUP_REQUEST_H_
#define _PDU_SESSION_RESOURCE_SETUP_REQUEST_H_

#include <optional>

#include "NgapUeMessage.hpp"
#include "PduSessionResourceSetupListSUReq.hpp"
#include "RanPagingPriority.hpp"
#include "UeAggregateMaxBitRate.hpp"

extern "C" {
#include "Ngap_InitialContextSetupRequest.h"
}

namespace oai::ngap {

class PduSessionResourceSetupRequestMsg : public NgapUeMessage {
 public:
  PduSessionResourceSetupRequestMsg();
  virtual ~PduSessionResourceSetupRequestMsg();

  void initialize();

  void setAmfUeNgapId(const uint64_t& id) override;
  void setRanUeNgapId(const uint32_t& id) override;
  bool decode(Ngap_NGAP_PDU_t* ngapMsgPdu) override;

  void setRanPagingPriority(const uint32_t& priority);
  bool getRanPagingPriority(uint32_t& priority) const;

  void setNasPdu(const bstring& pdu);
  bool getNasPdu(bstring& pdu) const;

  void setPduSessionResourceSetupRequestList(
      const std::vector<PDUSessionResourceSetupRequestItem_t>& list);
  bool getPduSessionResourceSetupRequestList(
      std::vector<PDUSessionResourceSetupRequestItem_t>& list) const;

  void setUeAggregateMaxBitRate(
      const uint64_t& bitRateDl, const uint64_t& bitRateUl);
  bool getUeAggregateMaxBitRate(uint64_t& bitRateDl, uint64_t& bitRateUl) const;

 private:
  Ngap_PDUSessionResourceSetupRequest_t* m_PduSessionResourceSetupRequestIes;

  std::optional<RanPagingPriority> m_RanPagingPriority;  // Optional
  std::optional<NasPdu> m_NasPdu;                        // Optional
  PduSessionResourceSetupListSUReq
      m_PduSessionResourceSetupRequestList;                      // Mandatory
  std::optional<UeAggregateMaxBitRate> m_UeAggregateMaxBitRate;  // Optional
};

}  // namespace oai::ngap
#endif
