/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_RELEASE_RESPONSE_H_
#define _PDU_SESSION_RESOURCE_RELEASE_RESPONSE_H_

#include "CriticalityDiagnostics.hpp"
#include "NgapUeMessage.hpp"
#include "PduSessionResourceReleasedListRelRes.hpp"
#include "UserLocationInformation.hpp"

namespace oai::ngap {

class PduSessionResourceReleaseResponseMsg : public NgapUeMessage {
 public:
  PduSessionResourceReleaseResponseMsg();
  virtual ~PduSessionResourceReleaseResponseMsg();

  void initialize();

  void setAmfUeNgapId(const uint64_t& id) override;
  void setRanUeNgapId(const uint32_t& id) override;
  bool decode(Ngap_NGAP_PDU_t* ngapMsgPdu) override;

  void setPduSessionResourceReleasedList(
      const std::vector<PDUSessionResourceReleasedItem_t>& list);
  bool getPduSessionResourceReleasedList(
      std::vector<PDUSessionResourceReleasedItem_t>& list) const;

  void setUserLocationInfoNr(const NrCgi_t& cig, const Tai_t& tai);
  bool getUserLocationInfoNr(NrCgi_t& cig, Tai_t& tai) const;

 private:
  Ngap_PDUSessionResourceReleaseResponse_t*
      m_PduSessionResourceReleaseResponseIes;

  PduSessionResourceReleasedListRelRes
      m_PduSessionResourceReleasedList;  // Mandatory
  std::optional<UserLocationInformation> m_UserLocationInformation;  // Optional
  // TODO: CriticalityDiagnostics *criticalityDiagnostics; //Optional
};

}  // namespace oai::ngap
#endif
