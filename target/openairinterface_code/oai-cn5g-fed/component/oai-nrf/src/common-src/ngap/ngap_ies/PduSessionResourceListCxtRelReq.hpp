/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_LIST_CXT_REL_REQ_H_
#define _PDU_SESSION_RESOURCE_LIST_CXT_REL_REQ_H_

#include <vector>

#include "PduSessionResourceItemCxtRelReq.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceListCxtRelReq.h"
}

namespace oai::ngap {

class PduSessionResourceListCxtRelReq {
 public:
  PduSessionResourceListCxtRelReq();
  virtual ~PduSessionResourceListCxtRelReq();

  void set(const std::vector<PduSessionResourceItemCxtRelReq>& list);
  void get(std::vector<PduSessionResourceItemCxtRelReq>& list) const;

  bool encode(
      Ngap_PDUSessionResourceListCxtRelReq_t& pduSessionResourceList) const;
  bool decode(
      const Ngap_PDUSessionResourceListCxtRelReq_t& pduSessionResourceList);

 private:
  std::vector<PduSessionResourceItemCxtRelReq> m_ItemList;
};

}  // namespace oai::ngap

#endif
