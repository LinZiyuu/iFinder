/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _DOWNLINK_NON_UE_ASSOCIATED_NRPPA_TRANSPORT_H_
#define _DOWNLINK_NON_UE_ASSOCIATED_NRPPA_TRANSPORT_H_

#include "NgapMessage.hpp"

extern "C" {
#include "Ngap_DownlinkNonUEAssociatedNRPPaTransport.h"
}

namespace oai::ngap {

class DownlinkNonUeAssociatedNrppaTransportMsg : public NgapMessage {
 public:
  DownlinkNonUeAssociatedNrppaTransportMsg();
  virtual ~DownlinkNonUeAssociatedNrppaTransportMsg();

  void initialize();

  bool decode(Ngap_NGAP_PDU_t* ngapMsgPdu) override;

  void setRoutingId(const bstring& pdu);
  void getRoutingId(bstring& pdu) const;

  void setNrppaPdu(const bstring& pdu);
  void getNrppaPdu(bstring& pdu) const;

 private:
  Ngap_DownlinkNonUEAssociatedNRPPaTransport_t*
      m_DownlinkNonUeAssociatedNrppaTransportIes;

  bstring m_RoutingId;  // Mandatory
  bstring m_NrppaPdu;   // Mandatory
};

}  // namespace oai::ngap
#endif
