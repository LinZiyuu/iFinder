/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_RELEASE_COMMAND_H_
#define _PDU_SESSION_RESOURCE_RELEASE_COMMAND_H_

#include <optional>

#include "NasPdu.hpp"
#include "NgapUeMessage.hpp"
#include "PduSessionResourceToReleaseListRelCmd.hpp"
#include "RanPagingPriority.hpp"

namespace oai::ngap {

class PduSessionResourceReleaseCommandMsg : public NgapUeMessage {
 public:
  PduSessionResourceReleaseCommandMsg();
  virtual ~PduSessionResourceReleaseCommandMsg();

  void initialize();

  void setAmfUeNgapId(const uint64_t& id) override;
  void setRanUeNgapId(const uint32_t& id) override;
  bool decode(Ngap_NGAP_PDU_t* ngapMsgPdu) override;

  void setRanPagingPriority(const uint32_t& priority);
  bool getRanPagingPriority(uint32_t& priority) const;

  void setNasPdu(const bstring& pdu);
  bool getNasPdu(bstring& pdu) const;

  void setPduSessionResourceToReleaseList(
      const std::vector<PDUSessionResourceToReleaseItem_t>& list);
  bool getPduSessionResourceToReleaseList(
      std::vector<PDUSessionResourceToReleaseItem_t>& list) const;

 private:
  Ngap_PDUSessionResourceReleaseCommand_t*
      m_PduSessionResourceReleaseCommandIes;

  std::optional<RanPagingPriority> m_RanPagingPriority;  // Optional
  std::optional<NasPdu> m_NasPdu;                        // Optional
  PduSessionResourceToReleaseListRelCmd
      m_PduSessionResourceToReleaseList;  // Mandatory
};

}  // namespace oai::ngap
#endif
