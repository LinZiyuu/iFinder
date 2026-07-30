/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _DRB_STATUS_UL18_H_
#define _DRB_STATUS_UL18_H_

#include "CountValueForPdcpSn18.hpp"

extern "C" {
#include "Ngap_DRBStatusUL18.h"
}

namespace oai::ngap {

class DrbStatusUl18 {
 public:
  DrbStatusUl18();
  virtual ~DrbStatusUl18();

  void get(CountValueForPdcpSn18& countValue) const;
  void set(const CountValueForPdcpSn18& countValue);

  bool encode(Ngap_DRBStatusUL18_t& ul18) const;
  bool decode(const Ngap_DRBStatusUL18_t& ul18);

 private:
  CountValueForPdcpSn18 m_PdcpValue;  // Mandatory
  // TODO: Receive Status of UL PDCP SDUs //Optional
};

}  // namespace oai::ngap
#endif
