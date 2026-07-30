/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _COUNT_VALUE_FOR_PDCP_SN_12_H_
#define _COUNT_VALUE_FOR_PDCP_SN_12_H_

extern "C" {
#include "Ngap_COUNTValueForPDCP-SN12.h"
}

namespace oai::ngap {
class CountValueForPdcpSn12 {
 public:
  CountValueForPdcpSn12();
  virtual ~CountValueForPdcpSn12(){};

  void set(const long& pDCP, const long& hfn_PDCP);
  void get(long& pDCP, long& hFN_PDCP) const;

  bool encode(Ngap_COUNTValueForPDCP_SN12_t& value) const;
  bool decode(const Ngap_COUNTValueForPDCP_SN12_t& value);

 private:
  long m_Pdcp;     // Mandatory (12 bits)
  long m_HfnPdcp;  // Mandatory (20 bits?)
};

}  // namespace oai::ngap
#endif
