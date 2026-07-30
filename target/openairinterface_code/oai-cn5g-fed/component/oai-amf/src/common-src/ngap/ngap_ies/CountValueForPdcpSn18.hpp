/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _COUNT_VALUE_FOR_PDCP_SN_18_H_
#define _COUNT_VALUE_FOR_PDCP_SN_18_H_

extern "C" {
#include "Ngap_COUNTValueForPDCP-SN18.h"
}

namespace oai::ngap {
class CountValueForPdcpSn18 {
 public:
  CountValueForPdcpSn18();
  virtual ~CountValueForPdcpSn18(){};

  void set(const long& pDCP, const long& hfn_PDCP);
  void get(long& pDCP, long& hFN_PDCP) const;

  bool encode(Ngap_COUNTValueForPDCP_SN18_t& countvalue) const;
  bool decode(const Ngap_COUNTValueForPDCP_SN18_t& countValue);

 private:
  long m_Pdcp;     // Mandatory (18 bits)
  long m_HfnPdcp;  // Mandatory (14 bits)
};

}  // namespace oai::ngap
#endif
