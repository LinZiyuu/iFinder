/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _NOTIFICATION_CONTROL_H_
#define _NOTIFICATION_CONTROL_H_

extern "C" {
#include "Ngap_NotificationControl.h"
}

namespace oai::ngap {

class NotificationControl {
 public:
  NotificationControl();
  virtual ~NotificationControl();

  void set(const e_Ngap_NotificationControl& value);
  bool get(e_Ngap_NotificationControl& value) const;

  bool encode(Ngap_NotificationControl_t&) const;
  bool decode(const Ngap_NotificationControl_t&);

 private:
  long m_NotificationControl;
};

}  // namespace oai::ngap

#endif
