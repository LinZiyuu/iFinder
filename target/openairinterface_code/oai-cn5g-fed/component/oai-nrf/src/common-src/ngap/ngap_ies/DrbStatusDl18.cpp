/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "DrbStatusDl18.hpp"
#include "logger_base.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
DrbStatusDl18::DrbStatusDl18() {}

//------------------------------------------------------------------------------
DrbStatusDl18::~DrbStatusDl18() {}

//------------------------------------------------------------------------------
void DrbStatusDl18::get(CountValueForPdcpSn18& value) const {
  value = m_DlCountValue;
}

//------------------------------------------------------------------------------
void DrbStatusDl18::set(const CountValueForPdcpSn18& value) {
  m_DlCountValue = value;
}

//------------------------------------------------------------------------------
bool DrbStatusDl18::encode(Ngap_DRBStatusDL18_t& dl18) const {
  if (!m_DlCountValue.encode(dl18.dL_COUNTValue)) {
    oai::logger::logger_common::ngap().error("Encode DRBStatusDL18 IE error");
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool DrbStatusDl18::decode(const Ngap_DRBStatusDL18_t& dl18) {
  if (!m_DlCountValue.decode(dl18.dL_COUNTValue)) {
    oai::logger::logger_common::ngap().error("Decode DRBStatusDL18 IE error");
    return false;
  }
  return true;
}
}  // namespace oai::ngap
