/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _AMF_STATUS_INDICATION_H_
#define _AMF_STATUS_INDICATION_H_

#include "MessageType.hpp"
#include "NgapIesStruct.hpp"
#include "NgapMessage.hpp"
#include "UnavailableGuamiList.hpp"

extern "C" {
#include "Ngap_AMFStatusIndication.h"
}

namespace oai::ngap {

class AmfStatusIndication : public NgapMessage {
 public:
  AmfStatusIndication();
  virtual ~AmfStatusIndication();

  void initialize();

  void setUnavailableGuamiList(const UnavailableGuamiList& list);
  void getUnavailableGuamiList(UnavailableGuamiList& list) const;

  bool decode(Ngap_NGAP_PDU_t* ngapMsgPdu) override;

 private:
  Ngap_AMFStatusIndication_t* m_AmfStatusIndicationIEs;

  UnavailableGuamiList m_UnavailableGuamiList;  // Mandatory
};
}  // namespace oai::ngap
#endif
