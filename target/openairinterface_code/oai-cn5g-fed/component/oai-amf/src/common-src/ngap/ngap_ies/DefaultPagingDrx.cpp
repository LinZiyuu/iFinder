/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "DefaultPagingDrx.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
DefaultPagingDrx::DefaultPagingDrx() {
  m_PagingDrx = Ngap_PagingDRX_v32;
}

//------------------------------------------------------------------------------
DefaultPagingDrx::~DefaultPagingDrx() {}

//------------------------------------------------------------------------------
void DefaultPagingDrx::set(const e_Ngap_PagingDRX& pagingDrx) {
  m_PagingDrx = pagingDrx;
}

//------------------------------------------------------------------------------
e_Ngap_PagingDRX DefaultPagingDrx::get() const {
  return m_PagingDrx;
}

//------------------------------------------------------------------------------
bool DefaultPagingDrx::encode(Ngap_PagingDRX_t& pagingDrx) const {
  pagingDrx = m_PagingDrx;
  return true;
}

//------------------------------------------------------------------------------
bool DefaultPagingDrx::decode(const Ngap_PagingDRX_t& pagingDrx) {
  switch (pagingDrx) {
    case 32: {
      m_PagingDrx = Ngap_PagingDRX_v32;
    } break;
    case 64: {
      m_PagingDrx = Ngap_PagingDRX_v64;
    } break;

    case 128: {
      m_PagingDrx = Ngap_PagingDRX_v128;
    } break;

    case 256: {
      m_PagingDrx = Ngap_PagingDRX_v256;
    } break;

    default: {
      m_PagingDrx = (e_Ngap_PagingDRX) pagingDrx;
    }
  }

  return true;
}

}  // namespace oai::ngap
