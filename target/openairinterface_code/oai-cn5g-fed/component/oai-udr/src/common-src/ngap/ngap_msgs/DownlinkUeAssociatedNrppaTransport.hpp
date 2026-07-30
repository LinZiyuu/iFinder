/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _DOWNLINK_UE_ASSOCIATED_NRPPA_TRANSPORT_H_
#define _DOWNLINK_UE_ASSOCIATED_NRPPA_TRANSPORT_H_

#include "AmfUeNgapId.hpp"
#include "MessageType.hpp"
#include "NasPdu.hpp"
#include "NgapUeMessage.hpp"
#include "RanPagingPriority.hpp"
#include "RanUeNgapId.hpp"

extern "C" {
#include "Ngap_DownlinkUEAssociatedNRPPaTransport.h"
}

namespace oai::ngap {

class DownlinkUeAssociatedNrppaTransportMsg : public NgapUeMessage {
 public:
  DownlinkUeAssociatedNrppaTransportMsg();
  virtual ~DownlinkUeAssociatedNrppaTransportMsg();

  void initialize();

  void setAmfUeNgapId(const uint64_t& id) override;
  void setRanUeNgapId(const uint32_t& id) override;
  bool decode(Ngap_NGAP_PDU_t* ngapMsgPdu) override;

  void setRoutingId(const bstring& pdu);
  void getRoutingId(bstring& pdu) const;

  void setNrppaPdu(const bstring& pdu);
  void getNrppaPdu(bstring& pdu) const;

 private:
  Ngap_DownlinkUEAssociatedNRPPaTransport_t*
      m_DownlinkUeAssociatedNrppaTransportIes;

  // AMF_UE_NGAP_ID  //Mandatory
  // RAN_UE_NGAP_ID //Mandatory
  bstring m_RoutingId;  // Mandatory
  bstring m_NrppaPdu;   // Mandatory
};

}  // namespace oai::ngap
#endif
