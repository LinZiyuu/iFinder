/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "NotificationControl.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
NotificationControl::NotificationControl() {
  m_NotificationControl = 0;
}

//------------------------------------------------------------------------------
NotificationControl::~NotificationControl() {}

//------------------------------------------------------------------------------
void NotificationControl::set(const e_Ngap_NotificationControl& value) {
  m_NotificationControl = value;
}

//------------------------------------------------------------------------------
bool NotificationControl::get(e_Ngap_NotificationControl& value) const {
  if (m_NotificationControl == Ngap_NotificationControl_notification_requested)
    value = Ngap_NotificationControl_notification_requested;
  else
    return 0;

  return true;
}

//------------------------------------------------------------------------------
bool NotificationControl::encode(
    Ngap_NotificationControl_t& notificationControl) const {
  notificationControl = m_NotificationControl;

  return true;
}

//------------------------------------------------------------------------------
bool NotificationControl::decode(
    const Ngap_NotificationControl_t& notificationControl) {
  m_NotificationControl = notificationControl;

  return true;
}
}  // namespace oai::ngap
