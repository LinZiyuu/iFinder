/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _UPLINK_UE_ASSOCIATED_NRPPA_TRANSPORT_H_
#define _UPLINK_UE_ASSOCIATED_NRPPA_TRANSPORT_H_

#include "NgapUeMessage.hpp"

extern "C" {
#include "Ngap_UplinkUEAssociatedNRPPaTransport.h"
}

namespace oai::ngap {

class UplinkUeAssociatedNrppaTransportMsg : public NgapUeMessage {
 public:
  UplinkUeAssociatedNrppaTransportMsg();
  virtual ~UplinkUeAssociatedNrppaTransportMsg();

  void initialize();

  void setAmfUeNgapId(const uint64_t& id) override;
  void setRanUeNgapId(const uint32_t& id) override;
  bool decode(Ngap_NGAP_PDU_t* ngapMsgPdu) override;

  void setRoutingId(const OCTET_STRING_t& pdu);
  void getRoutingId(OCTET_STRING_t& pdu) const;
  OCTET_STRING_t getRoutingId() const;

  void setNrppaPdu(const OCTET_STRING_t& pdu);
  void getNrppaPdu(OCTET_STRING_t& pdu) const;
  OCTET_STRING_t getNrppaPdu() const;

 private:
  Ngap_UplinkUEAssociatedNRPPaTransport_t*
      m_UplinkUeAssociatedNrppaTransportIes;

  // AMF_UE_NGAP_ID  //Mandatory
  // RAN_UE_NGAP_ID //Mandatory
  OCTET_STRING_t m_RoutingId;  // Mandatory
  OCTET_STRING_t m_NrppaPdu;   // Mandatory
};

}  // namespace oai::ngap
#endif
