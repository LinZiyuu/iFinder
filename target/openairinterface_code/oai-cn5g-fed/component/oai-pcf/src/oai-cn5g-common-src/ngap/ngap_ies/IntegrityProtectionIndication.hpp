/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _INTEGRITY_PROTECTION_INDICATION_H_
#define _INTEGRITY_PROTECTION_INDICATION_H_

extern "C" {
#include "Ngap_IntegrityProtectionIndication.h"
}

namespace oai::ngap {

class IntegrityProtectionIndication {
 public:
  IntegrityProtectionIndication();
  virtual ~IntegrityProtectionIndication();

  void set(const e_Ngap_IntegrityProtectionIndication& indication);
  bool get(long& indication) const;

  bool encode(Ngap_IntegrityProtectionIndication_t&) const;
  bool decode(const Ngap_IntegrityProtectionIndication_t&);

 private:
  long m_Indication;
};

}  // namespace oai::ngap

#endif
