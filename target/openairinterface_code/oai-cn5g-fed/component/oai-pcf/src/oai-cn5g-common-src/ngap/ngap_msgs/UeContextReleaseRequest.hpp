/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _UE_CONTEXT_RELEASE_REQUEST_H_
#define _UE_CONTEXT_RELEASE_REQUEST_H_

#include "Cause.hpp"
#include "NgapUeMessage.hpp"
#include "PduSessionResourceListCxtRelReq.hpp"

extern "C" {
#include "Ngap_UEContextReleaseRequest.h"
}

namespace oai::ngap {

class UeContextReleaseRequestMsg : public NgapUeMessage {
 public:
  UeContextReleaseRequestMsg();
  ~UeContextReleaseRequestMsg();

  void initialize();

  void setAmfUeNgapId(const uint64_t& id) override;
  void setRanUeNgapId(const uint32_t& id) override;
  bool decode(Ngap_NGAP_PDU_t* ngapMsgPdu) override;

  void setPduSessionResourceList(const PduSessionResourceListCxtRelReq&
                                     pdu_session_resource_list_cxt_rel_req);
  bool getPduSessionResourceList(
      PduSessionResourceListCxtRelReq& pdu_session_resource_list_cxt_rel_req)
      const;

  void addCauseIe();
  void setCauseRadioNetwork(const e_Ngap_CauseRadioNetwork& cause);
  bool getCauseRadioNetwork(e_Ngap_CauseRadioNetwork& cause) const;

 private:
  Ngap_UEContextReleaseRequest_t* m_UEContextReleaseRequestIes;

  // AMF_UE_NGAP_ID //Mandatory
  // RAN_UE_NGAP_ID //Mandatory
  std::optional<PduSessionResourceListCxtRelReq>
      m_PduSessionResourceListCxtRelReq;  // Optional
  Cause m_CauseValue;                     // Mandatory
};

}  // namespace oai::ngap

#endif
