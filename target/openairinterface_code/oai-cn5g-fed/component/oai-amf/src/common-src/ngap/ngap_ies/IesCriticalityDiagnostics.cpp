/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "IesCriticalityDiagnostics.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
IesCriticalityDiagnostics::IesCriticalityDiagnostics() {}

//------------------------------------------------------------------------------
IesCriticalityDiagnostics::~IesCriticalityDiagnostics() {}

//------------------------------------------------------------------------------
void IesCriticalityDiagnostics::setIeCriticality(
    const Ngap_Criticality_t& criticality) {
  m_Criticality = criticality;
}

//------------------------------------------------------------------------------
void IesCriticalityDiagnostics::setIeId(
    const Ngap_ProtocolIE_ID_t& protocolIeId) {
  m_ProtocolIeId = protocolIeId;
}

//------------------------------------------------------------------------------
void IesCriticalityDiagnostics::setTypeOfError(
    const Ngap_TypeOfError_t& typeOfError) {
  m_TypeOfError = typeOfError;
}

//------------------------------------------------------------------------------
void IesCriticalityDiagnostics::encode(
    Ngap_CriticalityDiagnostics_IE_Item_t& IE_Item) const {
  IE_Item.iECriticality = m_Criticality;
  IE_Item.iE_ID         = m_ProtocolIeId;
  IE_Item.typeOfError   = m_TypeOfError;
}

//------------------------------------------------------------------------------
void IesCriticalityDiagnostics::decode(
    const Ngap_CriticalityDiagnostics_IE_Item_t& pdu) {
  m_Criticality  = pdu.iECriticality;
  m_ProtocolIeId = pdu.iE_ID;
  m_TypeOfError  = pdu.typeOfError;
}

//------------------------------------------------------------------------------
Ngap_Criticality_t IesCriticalityDiagnostics::getIeCriticality() const {
  return m_Criticality;
}

//------------------------------------------------------------------------------
Ngap_ProtocolIE_ID_t IesCriticalityDiagnostics::getIeId() const {
  return m_ProtocolIeId;
}

//------------------------------------------------------------------------------
Ngap_TypeOfError_t IesCriticalityDiagnostics::getTypeOfError() const {
  return m_TypeOfError;
}
}  // namespace oai::ngap
