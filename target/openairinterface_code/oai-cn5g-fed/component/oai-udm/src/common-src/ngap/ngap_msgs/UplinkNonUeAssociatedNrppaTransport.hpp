/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _UPLINK_NON_UE_ASSOCIATED_NRPPA_TRANSPORT_H_
#define _UPLINK_NON_UE_ASSOCIATED_NRPPA_TRANSPORT_H_

#include "NgapMessage.hpp"

extern "C" {
#include "Ngap_UplinkNonUEAssociatedNRPPaTransport.h"
}

namespace oai::ngap {

class UplinkNonUeAssociatedNrppaTransportMsg : public NgapMessage {
 public:
  UplinkNonUeAssociatedNrppaTransportMsg();
  virtual ~UplinkNonUeAssociatedNrppaTransportMsg();

  void initialize();

  bool decode(Ngap_NGAP_PDU_t* ngapMsgPdu) override;

  void setRoutingId(const OCTET_STRING_t& pdu);
  void getRoutingId(OCTET_STRING_t& pdu) const;
  OCTET_STRING_t getRoutingId() const;

  void setNrppaPdu(const OCTET_STRING_t& pdu);
  void getNrppaPdu(OCTET_STRING_t& pdu) const;
  OCTET_STRING_t getNrppaPdu() const;

 private:
  Ngap_UplinkNonUEAssociatedNRPPaTransport_t*
      m_UplinkNonUeAssociatedNrppaTransportIes;

  OCTET_STRING_t m_RoutingId;  // Mandatory
  OCTET_STRING_t m_NrppaPdu;   // Mandatory
};

}  // namespace oai::ngap
#endif
