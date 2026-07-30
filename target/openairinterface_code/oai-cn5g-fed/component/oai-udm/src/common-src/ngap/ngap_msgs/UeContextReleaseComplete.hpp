/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _UE_CONTEXT_RELEASE_COMPLETE_H_
#define _UE_CONTEXT_RELEASE_COMPLETE_H_

#include <optional>

#include "NgapUeMessage.hpp"
#include "PduSessionResourceListCxtRelCpl.hpp"
#include "UserLocationInformation.hpp"

extern "C" {
#include "Ngap_UEContextReleaseComplete.h"
}

namespace oai::ngap {

class UEContextReleaseCompleteMsg : public NgapUeMessage {
 public:
  UEContextReleaseCompleteMsg();
  ~UEContextReleaseCompleteMsg();
  void initialize();

  void setAmfUeNgapId(const uint64_t& id) override;
  void setRanUeNgapId(const uint32_t& id) override;
  bool decode(Ngap_NGAP_PDU_t* ngapMsgPdu) override;

  void setUserLocationInfoNr(const NrCgi_t& cig, const Tai_t& tai);
  void getUserLocationInfoNr(NrCgi_t& cig, Tai_t& tai) const;

  void setPduSessionResourceCxtRelCplList(
      const std::vector<PDUSessionResourceCxtRelCplItem_t>& list);
  bool getPduSessionResourceCxtRelCplList(
      std::vector<PDUSessionResourceCxtRelCplItem_t>& list) const;

 private:
  Ngap_UEContextReleaseComplete_t* m_UEContextReleaseCompleteIes;
  // AMF_UE_NGAP_ID //Mandatory
  // RAN_UE_NGAP_ID //Mandatory
  std::optional<UserLocationInformation> m_UserLocationInformation;  // Optional
  // TODO: Information on Recommended Cells and RAN Nodes for Paging (Optional)
  std::optional<PduSessionResourceListCxtRelCpl>
      m_PduSessionResourceListCxtRelCpl;  // Optional
  // TODO: Criticality Diagnostics (Optional)
  // TODO: Paging Assistance Data for CE Capable UE (Optional, Rel 16.14.0)
};

}  // namespace oai::ngap

#endif
