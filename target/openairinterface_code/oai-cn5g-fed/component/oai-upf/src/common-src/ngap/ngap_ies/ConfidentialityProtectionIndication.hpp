/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _CONFIDENTIALITY_PROTECTION_INDICATION_H_
#define _CONFIDENTIALITY_PROTECTION_INDICATION_H_

extern "C" {
#include "Ngap_ConfidentialityProtectionIndication.h"
}

namespace oai::ngap {

class ConfidentialityProtectionIndication {
 public:
  ConfidentialityProtectionIndication();
  virtual ~ConfidentialityProtectionIndication(){};

  void set(const e_Ngap_ConfidentialityProtectionIndication& indication);
  bool get(long& indication) const;

  bool encode(Ngap_ConfidentialityProtectionIndication_t&) const;
  bool decode(const Ngap_ConfidentialityProtectionIndication_t&);

 private:
  long m_Indication;
};

}  // namespace oai::ngap

#endif
