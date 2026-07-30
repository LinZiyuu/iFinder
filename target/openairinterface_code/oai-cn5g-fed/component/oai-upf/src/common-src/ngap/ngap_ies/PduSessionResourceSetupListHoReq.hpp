/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef PDU_SESSION_RESOURCE_SETUP_LIST_HO_REQ_H_
#define PDU_SESSION_RESOURCE_SETUP_LIST_HO_REQ_H_

#include <vector>

#include "PduSessionResourceSetupItemHoReq.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceSetupListHOReq.h"
}

namespace oai::ngap {

class PduSessionResourceSetupListHoReq {
 public:
  PduSessionResourceSetupListHoReq();
  virtual ~PduSessionResourceSetupListHoReq();

  void set(const std::vector<PduSessionResourceSetupItemHoReq>& list);
  void get(std::vector<PduSessionResourceSetupItemHoReq>& list) const;

  bool encode(Ngap_PDUSessionResourceSetupListHOReq_t&
                  pduSessionResourceSetupListHOReq) const;
  bool decode(const Ngap_PDUSessionResourceSetupListHOReq_t&
                  pduSessionResourceSetupListHOReq);

 private:
  std::vector<PduSessionResourceSetupItemHoReq> m_ItemList;
};

}  // namespace oai::ngap

#endif
