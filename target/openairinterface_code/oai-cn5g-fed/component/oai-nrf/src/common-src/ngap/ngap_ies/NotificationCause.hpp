/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _NOTIFICATION_CAUSE_H_
#define _NOTIFICATION_CAUSE_H_

extern "C" {
#include "Ngap_NotificationCause.h"
}

namespace oai::ngap {

class NotificationCause {
 public:
  NotificationCause();
  virtual ~NotificationCause();

  void set(const long& value);
  bool get(long& value) const;

  bool encode(Ngap_NotificationCause_t&) const;
  bool decode(const Ngap_NotificationCause_t&);

 private:
  long m_NotificationCause;
};

}  // namespace oai::ngap

#endif
