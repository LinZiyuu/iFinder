/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "CountValueForPdcpSn12.hpp"

namespace oai::ngap {
//------------------------------------------------------------------------------
CountValueForPdcpSn12::CountValueForPdcpSn12() {
  m_Pdcp    = 0;
  m_HfnPdcp = 0;
}

//------------------------------------------------------------------------------
void CountValueForPdcpSn12::set(const long& pDCP, const long& hfn_PDCP) {
  m_Pdcp    = pDCP;
  m_HfnPdcp = hfn_PDCP;
}

//------------------------------------------------------------------------------
void CountValueForPdcpSn12::get(long& pDCP, long& hFN_PDCP) const {
  pDCP     = m_Pdcp;
  hFN_PDCP = m_HfnPdcp;
}

//------------------------------------------------------------------------------
bool CountValueForPdcpSn12::encode(Ngap_COUNTValueForPDCP_SN12_t& value) const {
  value.pDCP_SN12     = m_Pdcp;
  value.hFN_PDCP_SN12 = m_HfnPdcp;
  return true;
}

//------------------------------------------------------------------------------
bool CountValueForPdcpSn12::decode(const Ngap_COUNTValueForPDCP_SN12_t& value) {
  m_Pdcp    = value.pDCP_SN12;
  m_HfnPdcp = value.hFN_PDCP_SN12;
  return true;
}
}  // namespace oai::ngap
