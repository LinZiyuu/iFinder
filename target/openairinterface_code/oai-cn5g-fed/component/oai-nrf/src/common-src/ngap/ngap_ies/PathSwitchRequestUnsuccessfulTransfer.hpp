/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PATH_SWITCH_REQUEST_UNSUCCESSFUL_TRANSFER_H_
#define _PATH_SWITCH_REQUEST_UNSUCCESSFUL_TRANSFER_H_

#include "Cause.hpp"
#include "NgapIesStruct.hpp"

extern "C" {
#include "Ngap_PathSwitchRequestUnsuccessfulTransfer.h"
#include "Ngap_ProtocolIE-Field.h"
}

namespace oai::ngap {

class PathSwitchRequestUnsuccessfulTransfer {
 public:
  PathSwitchRequestUnsuccessfulTransfer();
  virtual ~PathSwitchRequestUnsuccessfulTransfer();

  void setCauseRadioNetwork(e_Ngap_CauseRadioNetwork causeValue);
  void setCauseTransport(e_Ngap_CauseTransport causeValue);
  void setCauseNas(e_Ngap_CauseNas causeValue);
  void setCauseProtocol(e_Ngap_CauseProtocol causeValue);
  void setCauseMisc(e_Ngap_CauseMisc causeValue);

  long getChoiceOfCause() const;
  long getCause() const;

  int encode(uint8_t* buf, int bufSize);
  bool decode(uint8_t* buf, int bufSize);

 private:
  Ngap_PathSwitchRequestUnsuccessfulTransfer_t*
      m_PathSwitchRequestUnsuccessfulTransferIe;

  Cause m_CauseValue;  // Mandatory
};

}  // namespace oai::ngap
#endif
