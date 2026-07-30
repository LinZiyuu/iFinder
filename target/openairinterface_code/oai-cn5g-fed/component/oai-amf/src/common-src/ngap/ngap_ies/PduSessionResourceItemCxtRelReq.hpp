/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_ITEM_CXT_REL_REQ_H_
#define _PDU_SESSION_RESOURCE_ITEM_CXT_REL_REQ_H_

#include "PduSessionId.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceItemCxtRelReq.h"
}

namespace oai::ngap {

class PduSessionResourceItemCxtRelReq {
 public:
  PduSessionResourceItemCxtRelReq();
  virtual ~PduSessionResourceItemCxtRelReq();

  void set(const PduSessionId& pduSessionId);
  void get(PduSessionId& pduSessionId) const;
  PduSessionId get() const;

  bool encode(
      Ngap_PDUSessionResourceItemCxtRelReq_t& pduSessionResourceItem) const;
  bool decode(
      const Ngap_PDUSessionResourceItemCxtRelReq_t& pduSessionResourceItem);

 private:
  PduSessionId m_PduSessionId;  // Mandatory
};

}  // namespace oai::ngap

#endif
