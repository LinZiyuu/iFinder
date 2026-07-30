/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _NG_SETUP_RESPONSE_H_
#define _NG_SETUP_RESPONSE_H_

#include "AmfName.hpp"
#include "MessageType.hpp"
#include "NgapIesStruct.hpp"
#include "NgapMessage.hpp"
#include "PlmnSupportList.hpp"
#include "RelativeAmfCapacity.hpp"
#include "ServedGuamiList.hpp"
#include "UeRetentionInformation.hpp"

extern "C" {
#include "Ngap_NGSetupResponse.h"
}

namespace oai::ngap {

class NgSetupResponseMsg : public NgapMessage {
 public:
  NgSetupResponseMsg();
  virtual ~NgSetupResponseMsg();

  void initialize();

  bool setAmfName(const std::string& name);
  bool getAmfName(std::string& name) const;

  void setGuamiList(std::vector<struct GuamiItem_s>& list);
  bool getGuamiList(std::vector<struct GuamiItem_s>& list) const;

  void setRelativeAmfCapacity(const long& capacity);
  long getRelativeAmfCapacity() const;

  void setPlmnSupportList(const PlmnSupportList& list);
  void getPlmnSupportList(PlmnSupportList& list) const;

  void setUeRetentionInformation(const UeRetentionInformation& value);
  void getUeRetentionInformation(
      std::optional<UeRetentionInformation>& value) const;

  bool decode(Ngap_NGAP_PDU_t* ngapMsgPdu) override;

 private:
  Ngap_NGSetupResponse_t* m_NgSetupResponsIes;

  AmfName m_AmfName;                          // Mandatory
  ServedGuamiList m_ServedGuamiList;          // Mandatory
  RelativeAmfCapacity m_RelativeAmfCapacity;  // Mandatory
  PlmnSupportList m_PlmnSupportList;          // Mandatory
  // TODO: CriticalityDiagnostics //Optional
  std::optional<UeRetentionInformation> m_UeRetentionInformation;  // Optional
  // TODO:IAB Supported (Optional, Rel 16.14.0)
  // TODO:Extended AMF Name (Optional, Rel 16.14.0)
};

}  // namespace oai::ngap
#endif
