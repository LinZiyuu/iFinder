/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _UPLINK_NAS_TRANSPORT_H_
#define _UPLINK_NAS_TRANSPORT_H_

#include "NasPdu.hpp"
#include "NgapUeMessage.hpp"
#include "UserLocationInformation.hpp"

extern "C" {
#include "Ngap_UplinkNASTransport.h"
}

namespace oai::ngap {

class UplinkNasTransportMsg : public NgapUeMessage {
 public:
  UplinkNasTransportMsg();
  virtual ~UplinkNasTransportMsg();

  void initialize();

  void setAmfUeNgapId(const uint64_t& id) override;
  void setRanUeNgapId(const uint32_t& id) override;
  bool decode(Ngap_NGAP_PDU_t* ngapMsgPdu) override;

  void setNasPdu(const bstring& pdu);
  bool getNasPdu(bstring& pdu) const;

  void setUserLocationInfoNr(const NrCgi_t& cig, const Tai_t& tai);
  bool getUserLocationInfoNr(NrCgi_t& cig, Tai_t& tai) const;

 private:
  Ngap_UplinkNASTransport_t* m_UplinkNasTransportIes;
  // AMF_UE_NGAP_ID //Mandatory
  // RAN_UE_NGAP_ID //Mandatory
  NasPdu m_NasPdu;                                    // Mandatory
  UserLocationInformation m_UserLocationInformation;  // Mandatory
  // TODO: W-AGF Identity Information (Optional, Rel 16.14.0)
  // TODO: TNGF Identity Information (Optional, Rel 16.14.0)
  // TODO: TWIF Identity Information (Optional, Rel 16.14.0)
};

}  // namespace oai::ngap
#endif
