/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "DrbStatusUl12.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
DrbStatusUl12::DrbStatusUl12() {}

//------------------------------------------------------------------------------
DrbStatusUl12::~DrbStatusUl12() {}

//------------------------------------------------------------------------------
void DrbStatusUl12::get(CountValueForPdcpSn12& countValue) const {
  countValue = m_PdcpValue;
}

//------------------------------------------------------------------------------
void DrbStatusUl12::set(const CountValueForPdcpSn12& countValue) {
  m_PdcpValue = countValue;
}

//------------------------------------------------------------------------------
bool DrbStatusUl12::encode(Ngap_DRBStatusUL12_t& ul12) const {
  if (!m_PdcpValue.encode(ul12.uL_COUNTValue)) {
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool DrbStatusUl12::decode(const Ngap_DRBStatusUL12_t& ul12) {
  if (!m_PdcpValue.decode(ul12.uL_COUNTValue)) {
    return false;
  }
  return true;
}
}  // namespace oai::ngap
