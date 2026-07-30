/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _NG_SETUP_FAILURE_H_
#define _NG_SETUP_FAILURE_H_

#include <optional>

#include "Cause.hpp"
#include "MessageType.hpp"
#include "NgapMessage.hpp"
#include "TimeToWait.hpp"

namespace oai::ngap {

class NgSetupFailureMsg : public NgapMessage {
 public:
  NgSetupFailureMsg();
  virtual ~NgSetupFailureMsg();

  void initialize();

  void set(
      const e_Ngap_CauseRadioNetwork& causeValue,
      const e_Ngap_TimeToWait& timeToWait);
  void set(
      const e_Ngap_CauseTransport& causeValue,
      const e_Ngap_TimeToWait& timeToWait);
  void set(
      const e_Ngap_CauseNas& causeValue, const e_Ngap_TimeToWait& timeToWait);
  void set(
      const e_Ngap_CauseProtocol& causeValue,
      const e_Ngap_TimeToWait& timeToWait);
  void set(
      const e_Ngap_CauseMisc& causeValue, const e_Ngap_TimeToWait& timeToWait);

  void setCauseRadioNetwork(const e_Ngap_CauseRadioNetwork& causeValue);
  bool getCauseRadioNetwork(e_Ngap_CauseRadioNetwork&) const;

  void setCauseTransport(const e_Ngap_CauseTransport& causeValue);
  bool getCauseTransport(e_Ngap_CauseTransport&) const;

  void setCauseNas(const e_Ngap_CauseNas& causeValue);
  bool getCauseNas(e_Ngap_CauseNas&) const;

  void setCauseProtocol(const e_Ngap_CauseProtocol& causeValue);
  bool getCauseProtocol(e_Ngap_CauseProtocol&) const;

  void setCauseMisc(const e_Ngap_CauseMisc& causeValue);
  bool getCauseMisc(e_Ngap_CauseMisc&) const;

  bool getCauseType(Ngap_Cause_PR&) const;

  bool getTimeToWait(e_Ngap_TimeToWait&) const;
  void setTimeToWait(const e_Ngap_TimeToWait&);

  bool decode(Ngap_NGAP_PDU_t* ngapMsgPdu) override;

 private:
  Ngap_NGSetupFailure_t* m_NgSetupFailureIes;
  Cause m_Cause;                           // Mandatory
  std::optional<TimeToWait> m_TimeToWait;  // Optional
  // TODO: CriticalityDiagnostics *criticalityDiagnostics; //Optional

  void addCauseIe();
  void addTimeToWaitIE();
};
}  // namespace oai::ngap
#endif
