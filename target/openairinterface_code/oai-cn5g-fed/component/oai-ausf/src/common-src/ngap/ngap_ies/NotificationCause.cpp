/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "NotificationCause.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
NotificationCause::NotificationCause() {
  m_NotificationCause = 0;
}

//------------------------------------------------------------------------------
NotificationCause::~NotificationCause() {}

//------------------------------------------------------------------------------
void NotificationCause::set(const long& value) {
  m_NotificationCause = value;
}

//------------------------------------------------------------------------------
bool NotificationCause::get(long& value) const {
  value = m_NotificationCause;
  return true;
}

//------------------------------------------------------------------------------
bool NotificationCause::encode(
    Ngap_NotificationCause_t& NotificationCause) const {
  NotificationCause = m_NotificationCause;

  return true;
}

//------------------------------------------------------------------------------
bool NotificationCause::decode(
    const Ngap_NotificationCause_t& NotificationCause) {
  m_NotificationCause = NotificationCause;

  return true;
}
}  // namespace oai::ngap
