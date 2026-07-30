/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_SETUP_LIST_SU_REQ_H_
#define _PDU_SESSION_RESOURCE_SETUP_LIST_SU_REQ_H_

#include <vector>

#include "PduSessionResourceSetupItemSUReq.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceSetupListSUReq.h"
}

namespace oai::ngap {

class PduSessionResourceSetupListSUReq {
 public:
  PduSessionResourceSetupListSUReq();
  virtual ~PduSessionResourceSetupListSUReq();

  void set(const std::vector<PduSessionResourceSetupItemSUReq>& list);
  void get(std::vector<PduSessionResourceSetupItemSUReq>& list) const;

  bool encode(
      Ngap_PDUSessionResourceSetupListSUReq_t& pduSessionResourceList) const;
  bool decode(
      const Ngap_PDUSessionResourceSetupListSUReq_t& pduSessionResourceList);

 private:
  std::vector<PduSessionResourceSetupItemSUReq> m_ItemList;
};

}  // namespace oai::ngap

#endif
