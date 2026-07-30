/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _REROUTE_NAS_REQUEST_H_
#define _REROUTE_NAS_REQUEST_H_

#include "AllowedNssai.hpp"
#include "AmfSetId.hpp"
#include "NgapMessage.hpp"

extern "C" {
#include "Ngap_RerouteNASRequest.h"
}

namespace oai::ngap {

class RerouteNasRequest : public NgapMessage {
 public:
  RerouteNasRequest();
  virtual ~RerouteNasRequest();

  void initialize();
  bool decode(Ngap_NGAP_PDU_t* ngap_msg_pdu) override;

  void setAmfUeNgapId(const uint64_t& id);  // 40 bits
  bool getAmfUeNgapId(uint64_t& id) const;

  void setRanUeNgapId(const uint32_t& id);  // 32 bits
  uint32_t getRanUeNgapId() const;

  void setNgapMessage(const OCTET_STRING_t& message);
  bool getNgapMessage(OCTET_STRING_t& message) const;

  bool setAmfSetId(const uint16_t& amfSetId);
  void getAmfSetId(std::string& amfSetId) const;

  void setAllowedNssai(const std::vector<S_Nssai>& list);
  bool getAllowedNssai(std::vector<S_Nssai>& list) const;

 private:
  Ngap_RerouteNASRequest_t* m_RerouteNASRequestIes;

  RanUeNgapId m_RanUeNgapId;                   // Mandatory
  std::optional<AmfUeNgapId> m_AmfUeNgapId;    // Optional
  OCTET_STRING_t m_NgapMessage;                // Mandatory
  AmfSetId m_AmfSetId;                         // Mandatory
  std::optional<AllowedNSSAI> m_AllowedNssai;  // Optional
  // SourceToTarget-AMFInformationReroute //Optional
};

}  // namespace oai::ngap
#endif
