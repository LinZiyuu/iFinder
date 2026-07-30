/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_SETUP_LIST_CXT_REQ_H_
#define _PDU_SESSION_RESOURCE_SETUP_LIST_CXT_REQ_H_

#include <vector>

#include "PduSessionResourceSetupItemCxtReq.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceSetupListCxtReq.h"
}

namespace oai::ngap {

class PduSessionResourceSetupListCxtReq {
 public:
  PduSessionResourceSetupListCxtReq();
  virtual ~PduSessionResourceSetupListCxtReq();

  void set(const std::vector<PduSessionResourceSetupItemCxtReq>& itemList);
  void get(std::vector<PduSessionResourceSetupItemCxtReq>& itemList) const;

  bool encode(Ngap_PDUSessionResourceSetupListCxtReq_t&
                  pduSessionResourceSetupListCxtReq) const;
  bool decode(const Ngap_PDUSessionResourceSetupListCxtReq_t&
                  pduSessionResourceSetupListCxtReq);

 private:
  std::vector<PduSessionResourceSetupItemCxtReq> m_ItemList;
};

}  // namespace oai::ngap

#endif
