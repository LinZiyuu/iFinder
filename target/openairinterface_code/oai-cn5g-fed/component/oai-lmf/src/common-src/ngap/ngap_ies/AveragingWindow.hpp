/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _AVERAGING_WINDOW_H_
#define _AVERAGING_WINDOW_H_

extern "C" {
#include "Ngap_AveragingWindow.h"
}

namespace oai::ngap {

class AveragingWindow {
 public:
  AveragingWindow();
  virtual ~AveragingWindow();

  void set(const long& value);
  bool get(long& value) const;

  bool encode(Ngap_AveragingWindow_t&) const;
  bool decode(const Ngap_AveragingWindow_t&);

 private:
  long m_AveragingWindow;  // Madatory
};

}  // namespace oai::ngap

#endif
