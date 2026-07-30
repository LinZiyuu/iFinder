/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _UE_RADIO_CAPABILITY_INFO_INDICATION_H_
#define _UE_RADIO_CAPABILITY_INFO_INDICATION_H_

#include "NgapUeMessage.hpp"
#include "UeRadioCapability.hpp"
#include "UeRadioCapabilityForPaging.hpp"

extern "C" {
#include "Ngap_UERadioCapabilityInfoIndication.h"
}

namespace oai::ngap {

class UeRadioCapabilityInfoIndicationMsg : public NgapUeMessage {
 public:
  UeRadioCapabilityInfoIndicationMsg();
  virtual ~UeRadioCapabilityInfoIndicationMsg();

  void initialize();

  void setAmfUeNgapId(const uint64_t& id) override;
  void setRanUeNgapId(const uint32_t& id) override;
  bool decode(Ngap_NGAP_PDU_t* ngapMsgPdu) override;

  void setUeRadioCapability(const OCTET_STRING_t& capability);
  void getUeRadioCapability(OCTET_STRING_t& capability) const;

  void setUeRadioCapabilityForPaging(
      const OCTET_STRING_t& ueRadioCapabilityForPagingOfNr,
      const OCTET_STRING_t& ueRadioCapabilityForPagingOfEutra);
  bool getUeRadioCapabilityForPaging(
      OCTET_STRING_t& ueRadioCapabilityForPagingOfNr,
      OCTET_STRING_t& ueRadioCapabilityForPagingOfEutra) const;

 private:
  Ngap_UERadioCapabilityInfoIndication_t* m_UeRadioCapabilityInfoIndicationIes;
  // AMF_UE_NGAP_ID //Mandatory
  // RAN_UE_NGAP_ID //Mandatory
  UeRadioCapability m_UeRadioCapability;  // Mandatory
  std::optional<UeRadioCapabilityForPaging>
      m_UeRadioCapabilityForPaging;  // Optional
  // TODO: UE Radio Capability – E-UTRA Format (Optional, Rel 16.14.0)
};

}  // namespace oai::ngap
#endif
