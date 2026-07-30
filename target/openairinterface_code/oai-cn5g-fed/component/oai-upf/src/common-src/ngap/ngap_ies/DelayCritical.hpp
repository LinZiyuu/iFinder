/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _DELAY_CRITICAL_H_
#define _DELAY_CRITICAL_H_

extern "C" {
#include "Ngap_DelayCritical.h"
}

namespace oai::ngap {

class DelayCritical {
 public:
  DelayCritical();
  virtual ~DelayCritical();

  void set(const e_Ngap_DelayCritical& value);
  bool get(e_Ngap_DelayCritical& value) const;

  bool encode(Ngap_DelayCritical_t&) const;
  bool decode(const Ngap_DelayCritical_t&);

 private:
  long m_DelayCritical;
};

}  // namespace oai::ngap

#endif
