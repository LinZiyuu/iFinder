/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _FIVEQI_H_
#define _FIVEQI_H_

extern "C" {
#include "Ngap_FiveQI.h"
}

namespace oai::ngap {

class FiveQI {
 public:
  FiveQI();
  virtual ~FiveQI();

  void set(const long& value);
  bool get(long& value) const;

  bool encode(Ngap_FiveQI_t&) const;
  bool decode(const Ngap_FiveQI_t&);

 private:
  long m_FiveQI;
};

}  // namespace oai::ngap

#endif
