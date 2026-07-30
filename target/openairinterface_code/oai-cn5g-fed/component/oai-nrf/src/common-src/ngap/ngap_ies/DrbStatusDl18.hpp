/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _DRB_STATUS_DL18_H_
#define _DRB_STATUS_DL18_H_

#include "CountValueForPdcpSn18.hpp"

extern "C" {
#include "Ngap_DRBStatusDL18.h"
}

namespace oai::ngap {

class DrbStatusDl18 {
 public:
  DrbStatusDl18();
  virtual ~DrbStatusDl18();

  void get(CountValueForPdcpSn18& value) const;
  void set(const CountValueForPdcpSn18& value);

  bool encode(Ngap_DRBStatusDL18_t& dl18) const;
  bool decode(const Ngap_DRBStatusDL18_t& dl18);

 private:
  CountValueForPdcpSn18 m_DlCountValue;  // Mandatory
};
}  // namespace oai::ngap
#endif
