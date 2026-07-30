/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _UE_CONTEXT_REQUEST_H_
#define _UE_CONTEXT_REQUEST_H_

extern "C" {
#include "Ngap_UEContextRequest.h"
}

namespace oai::ngap {

class UeContextRequest {
 public:
  UeContextRequest();
  UeContextRequest(const e_Ngap_UEContextRequest& ueContextRequest);
  virtual ~UeContextRequest();

  void set(const e_Ngap_UEContextRequest& ueContextRequest);
  int get() const;

  bool encode(Ngap_UEContextRequest_t& ueContextRequest) const;
  bool decode(const Ngap_UEContextRequest_t& ueContextRequest);

 private:
  int m_UeContextRequest;
};

}  // namespace oai::ngap

#endif
