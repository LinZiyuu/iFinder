/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "IndexToRfsp.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
IndexToRfsp::IndexToRfsp() {
  m_Index = 0;
}
//------------------------------------------------------------------------------
IndexToRfsp::IndexToRfsp(const uint32_t& index) : m_Index(index) {}
//------------------------------------------------------------------------------
IndexToRfsp::~IndexToRfsp() {}

//------------------------------------------------------------------------------
void IndexToRfsp::set(const uint32_t& index) {
  m_Index = index;
}

//------------------------------------------------------------------------------
uint32_t IndexToRfsp::get() const {
  return m_Index;
}

//------------------------------------------------------------------------------
bool IndexToRfsp::encode(Ngap_IndexToRFSP_t& index) const {
  index = m_Index;
  return true;
}

//------------------------------------------------------------------------------
bool IndexToRfsp::decode(const Ngap_IndexToRFSP_t& index) {
  m_Index = index;
  return true;
}
}  // namespace oai::ngap
