/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _MESSAGE_TYPE_H_
#define _MESSAGE_TYPE_H_

extern "C" {
#include "Ngap_Criticality.h"
#include "Ngap_InitiatingMessage.h"
#include "Ngap_NGAP-PDU.h"
#include "Ngap_ProcedureCode.h"
#include "Ngap_SuccessfulOutcome.h"
#include "Ngap_UnsuccessfulOutcome.h"
}

namespace oai::ngap {

class MessageType {
 public:
  MessageType();
  MessageType(
      const Ngap_ProcedureCode_t& procedureCode,
      Ngap_NGAP_PDU_PR m_typeOfMessage);
  virtual ~MessageType();

  void setProcedureCode(const Ngap_ProcedureCode_t& procedureCode);
  Ngap_ProcedureCode_t getProcedureCode() const;

  void setTypeOfMessage(Ngap_NGAP_PDU_PR typeOfMessage);
  Ngap_NGAP_PDU_PR getTypeOfMessage() const;

  void setCriticality(Ngap_Criticality criticality);
  Ngap_Criticality getCriticality() const;

  void setValuePresent(Ngap_InitiatingMessage__value_PR valuePresent);
  void setValuePresent(Ngap_SuccessfulOutcome__value_PR valuePresent);
  void setValuePresent(Ngap_UnsuccessfulOutcome__value_PR valuePresent);

  int encode(Ngap_NGAP_PDU_t&) const;
  // TODO: void decode(const Ngap_NGAP_PDU_t&);

 private:
  Ngap_ProcedureCode_t m_ProcedureCode;  // Ngap_ProcedureCode.h
  Ngap_NGAP_PDU_PR m_TypeOfMessage;      // Ngap_NGAP-PDU.h
  Ngap_Criticality m_Criticality;        // Ngap_Criticality.h

  Ngap_InitiatingMessage__value_PR
      m_InitiatingMsgValuePresent;  // Ngap_InitiatingMessage.h
  Ngap_SuccessfulOutcome__value_PR
      m_SuccessfulOutcomeValuePresent;  // Ngap_SuccessfulOutcome.h
  Ngap_UnsuccessfulOutcome__value_PR
      m_UnsuccessfulOutcomeValuePresent;  // Ngap_UnsuccessfulOutcome.h
};
}  // namespace oai::ngap

#endif
