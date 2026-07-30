/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _DRB_STATUS_DL12_H_
#define _DRB_STATUS_DL12_H_

#include "CountValueForPdcpSn12.hpp"

extern "C" {
#include "Ngap_DRBStatusDL12.h"
}

namespace oai::ngap {

class DrbStatusDl12 {
 public:
  DrbStatusDl12();
  virtual ~DrbStatusDl12();

  void get(CountValueForPdcpSn12& value) const;
  void set(const CountValueForPdcpSn12& value);

  bool encode(Ngap_DRBStatusDL12_t& dl12) const;
  bool decode(const Ngap_DRBStatusDL12_t& dl12);

 private:
  CountValueForPdcpSn12 m_DlCountValue;  // Mandatory
};
}  // namespace oai::ngap
#endif
