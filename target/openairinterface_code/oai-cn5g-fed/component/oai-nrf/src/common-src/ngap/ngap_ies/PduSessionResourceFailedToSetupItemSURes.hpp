/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_FAILED_TO_SETUP_ITEM_SU_RES_H_
#define _PDU_SESSION_RESOURCE_FAILED_TO_SETUP_ITEM_SU_RES_H_

#include "PduSessionId.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceFailedToSetupItemSURes.h"
}

namespace oai::ngap {

class PduSessionResourceFailedToSetupItemSURes {
 public:
  PduSessionResourceFailedToSetupItemSURes();
  virtual ~PduSessionResourceFailedToSetupItemSURes();

  void set(
      const PduSessionId& pduSessionId,
      const OCTET_STRING_t& pduSessionResource);
  void get(
      PduSessionId& pduSessionId, OCTET_STRING_t& pduSessionResource) const;

  bool encode(Ngap_PDUSessionResourceFailedToSetupItemSURes_t&
                  pduSessionResourceItem) const;
  bool decode(const Ngap_PDUSessionResourceFailedToSetupItemSURes_t&
                  pduSessionResourceItem);

 private:
  PduSessionId m_PduSessionId;
  OCTET_STRING_t m_PduSessionResourceSetupUnsuccessfulTransfer;
};

}  // namespace oai::ngap

#endif
