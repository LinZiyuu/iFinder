/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "UeContextRequest.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
UeContextRequest::UeContextRequest() {
  m_UeContextRequest = -1;
}

//------------------------------------------------------------------------------
UeContextRequest::UeContextRequest(
    const e_Ngap_UEContextRequest& ueContextRequest)
    : m_UeContextRequest(ueContextRequest) {}
//------------------------------------------------------------------------------
UeContextRequest::~UeContextRequest() {}

//------------------------------------------------------------------------------
void UeContextRequest::set(const e_Ngap_UEContextRequest& ueContextRequest) {
  m_UeContextRequest = ueContextRequest;
}

//------------------------------------------------------------------------------
int UeContextRequest::get() const {
  return m_UeContextRequest;
}

//------------------------------------------------------------------------------
bool UeContextRequest::encode(Ngap_UEContextRequest_t& ueContextRequest) const {
  ueContextRequest = m_UeContextRequest;
  return true;
}

//------------------------------------------------------------------------------
bool UeContextRequest::decode(const Ngap_UEContextRequest_t& ueContextRequest) {
  m_UeContextRequest = ueContextRequest;
  return true;
}
}  // namespace oai::ngap
