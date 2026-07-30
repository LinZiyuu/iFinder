/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "AveragingWindow.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
AveragingWindow::AveragingWindow() {
  m_AveragingWindow = 0;
}

//------------------------------------------------------------------------------
AveragingWindow::~AveragingWindow() {}

//------------------------------------------------------------------------------
void AveragingWindow::set(const long& value) {
  m_AveragingWindow = value;
}

//------------------------------------------------------------------------------
bool AveragingWindow::get(long& value) const {
  value = m_AveragingWindow;

  return true;
}

//------------------------------------------------------------------------------
bool AveragingWindow::encode(Ngap_AveragingWindow_t& value) const {
  value = m_AveragingWindow;

  return true;
}

//------------------------------------------------------------------------------
bool AveragingWindow::decode(const Ngap_AveragingWindow_t& value) {
  m_AveragingWindow = value;

  return true;
}
}  // namespace oai::ngap
