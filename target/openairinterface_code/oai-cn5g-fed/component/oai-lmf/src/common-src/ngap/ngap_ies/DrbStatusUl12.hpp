/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _DRB_STATUS_UL12_H_
#define _DRB_STATUS_UL12_H_

#include "CountValueForPdcpSn12.hpp"

extern "C" {
#include "Ngap_DRBStatusUL12.h"
}

namespace oai::ngap {

class DrbStatusUl12 {
 public:
  DrbStatusUl12();
  virtual ~DrbStatusUl12();

  void get(CountValueForPdcpSn12& count_value) const;
  void set(const CountValueForPdcpSn12& count_value);

  bool encode(Ngap_DRBStatusUL12_t& ul12) const;
  bool decode(const Ngap_DRBStatusUL12_t& ul12);

 private:
  CountValueForPdcpSn12 m_PdcpValue;  // Mandatory
  // TODO: Receive Status of UL PDCP SDUs //Optional
};

}  // namespace oai::ngap
#endif
