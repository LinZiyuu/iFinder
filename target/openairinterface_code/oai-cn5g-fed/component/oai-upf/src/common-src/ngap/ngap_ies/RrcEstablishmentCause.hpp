/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _RRC_ESTABLISHMENT_CAUSE_H_
#define _RRC_ESTABLISHMENT_CAUSE_H_

extern "C" {
#include "Ngap_RRCEstablishmentCause.h"
}

namespace oai::ngap {

class RrcEstablishmentCause {
 public:
  RrcEstablishmentCause();
  virtual ~RrcEstablishmentCause();

  void set(const e_Ngap_RRCEstablishmentCause& cause);
  int get() const;

  bool encode(Ngap_RRCEstablishmentCause_t&) const;
  bool decode(Ngap_RRCEstablishmentCause_t);

 private:
  int m_Cause;
};

}  // namespace oai::ngap

#endif
