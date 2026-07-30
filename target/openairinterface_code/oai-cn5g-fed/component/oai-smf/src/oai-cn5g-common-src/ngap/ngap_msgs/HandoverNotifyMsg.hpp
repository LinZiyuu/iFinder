/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _HANDOVER_NOTIFY_MSG_H_
#define _HANDOVER_NOTIFY_MSG_H_

#include "AmfUeNgapId.hpp"
#include "NgapUeMessage.hpp"
#include "UserLocationInformation.hpp"

extern "C" {
#include "Ngap_HandoverNotify.h"
}

namespace oai::ngap {
class HandoverNotifyMsg : public NgapUeMessage {
 public:
  HandoverNotifyMsg();
  virtual ~HandoverNotifyMsg();

  void initialize();
  void setAmfUeNgapId(const uint64_t& id) override;
  void setRanUeNgapId(const uint32_t& id) override;
  bool decode(Ngap_NGAP_PDU_t* ngapMsgPdu) override;

  void setUserLocationInfoNr(const NrCgi_t& cig, const Tai_t& tai);
  bool getUserLocationInfoNr(NrCgi_t& cig, Tai_t& tai) const;

 private:
  Ngap_HandoverNotify_t* m_HandoverNotifyIes;
  // AMF_UE_NGAP_ID (Mandatory)
  // RAN_UE_NGAP_ID (Mandatory)
  UserLocationInformation m_UserLocationInformation;  // Mandatory
  // TODO: Notify Source NG-RAN Node (Optional, Rel 16.14.0)
};

}  // namespace oai::ngap
#endif
