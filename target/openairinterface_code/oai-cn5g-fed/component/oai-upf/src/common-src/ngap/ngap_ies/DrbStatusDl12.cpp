/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "DrbStatusDl12.hpp"
#include "logger_base.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
DrbStatusDl12::DrbStatusDl12() {}

//------------------------------------------------------------------------------
DrbStatusDl12::~DrbStatusDl12() {}

//------------------------------------------------------------------------------
void DrbStatusDl12::get(CountValueForPdcpSn12& value) const {
  value = m_DlCountValue;
}

//------------------------------------------------------------------------------
void DrbStatusDl12::set(const CountValueForPdcpSn12& value) {
  m_DlCountValue = value;
}

//------------------------------------------------------------------------------
bool DrbStatusDl12::encode(Ngap_DRBStatusDL12_t& dl12) const {
  if (!m_DlCountValue.encode(dl12.dL_COUNTValue)) {
    oai::logger::logger_common::ngap().error("Encode DrbStatusDl12 IE error");
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool DrbStatusDl12::decode(const Ngap_DRBStatusDL12_t& dl12) {
  if (!m_DlCountValue.decode(dl12.dL_COUNTValue)) {
    oai::logger::logger_common::ngap().error("Decode DrbStatusDl12 IE error");
    return false;
  }
  return true;
}
}  // namespace oai::ngap
