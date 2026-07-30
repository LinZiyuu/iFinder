/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _IES_CRITICALITY_DIAGNOSTICS_H_
#define _IES_CRITICALITY_DIAGNOSTICS_H_

extern "C" {
#include "Ngap_CriticalityDiagnostics-IE-Item.h"
}

namespace oai::ngap {

class IesCriticalityDiagnostics {
 public:
  IesCriticalityDiagnostics();
  virtual ~IesCriticalityDiagnostics();

  void setIeCriticality(const Ngap_Criticality_t&);
  Ngap_Criticality_t getIeCriticality() const;

  void setIeId(const Ngap_ProtocolIE_ID_t&);
  Ngap_ProtocolIE_ID_t getIeId() const;

  void setTypeOfError(const Ngap_TypeOfError_t&);
  Ngap_TypeOfError_t getTypeOfError() const;

  void encode(Ngap_CriticalityDiagnostics_IE_Item_t&) const;
  void decode(const Ngap_CriticalityDiagnostics_IE_Item_t&);

 private:
  Ngap_Criticality_t m_Criticality;     // Mandatory
  Ngap_ProtocolIE_ID_t m_ProtocolIeId;  // Mandatory
  Ngap_TypeOfError_t m_TypeOfError;     // Mandatory
};
}  // namespace oai::ngap

#endif
