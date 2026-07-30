/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _CAUSE_H_
#define _CAUSE_H_

extern "C" {
#include "Ngap_Cause.h"
}

namespace oai::ngap {

class Cause {
 public:
  Cause();
  virtual ~Cause();

  void setChoiceOfCause(const Ngap_Cause_PR& cause_present);
  Ngap_Cause_PR getChoiceOfCause() const;

  void set(const long& value);
  long get() const;

  void set(const long& value, const Ngap_Cause_PR& cause_present);

  bool encode(Ngap_Cause_t& cause) const;
  bool decode(const Ngap_Cause_t& cause);

 private:
  long m_CauseValue;
  Ngap_Cause_PR m_CausePresent;
};
}  // namespace oai::ngap

#endif
